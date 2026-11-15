# eap.py
#
"""EAP-Message reassembly and State session binding (RFC 3579).

A RADIUS server that terminates 802.1X carries one EAP packet per
Access-Request, fragmented over as many EAP-Message attributes as its
length needs (each attribute holds at most 253 octets). Concatenating
the attributes without validation hands truncated or glued-together EAP
packets to the authenticator, and accepting a State attribute without
checking which NAS session it was issued for lets one session's MFA
exchange leak into another.

:class:`EAPSessionTracker` binds both to a session key ``(nas,
session)``: the fragments of a request must reassemble into exactly the
EAP packet its header declares, a retransmitted message is detected, and
a State is only valid for the NAS session it was bound to. Requests that
fail the checks raise :class:`EAPFragmentError` or :class:`EAPStateError`
before anything reaches the authentication state machine; an unknown
State is answered with a deterministic Access-Reject.
"""

__docformat__ = "restructuredtext en"

from collections import deque
import struct

from pyrad.packet import PacketError

# Attribute codes: EAP-Message (RFC 3579 section 2.1) and
# State (RFC 2865 section 5.24)
EAP_MESSAGE = 79
STATE = 24

# An EAP packet is at least the Code/Identifier/Length header; a RADIUS
# packet is at most 4096 octets, so an EAP message cannot be longer.
EAP_HEADER_LENGTH = 4
MAX_EAP_MESSAGE_LENGTH = 4096

# EAP Identifiers of recently completed messages, kept per session to
# detect retransmissions and replays. EAP retransmits within seconds, so
# a small window suffices; identifiers are reused once it slides past.
COMPLETED_IDS = 8


class EAPFragmentError(PacketError):
    """The EAP-Message fragments of a request cannot be reassembled.

    Raised for empty fragments, a first fragment too short for the EAP
    header, an invalid declared length, a message that is shorter or
    longer than its declared length, and retransmitted or interleaved
    fragments. The request must not enter the authentication state
    machine.

    The error carries only the fragment index and the fragment length,
    never EAP content, so it is safe to log.

    :ivar index: index of the offending fragment in the request
    :type index: int
    :ivar length: length of the offending fragment in octets
    :type length: int
    """

    def __init__(self, index, length, reason):
        self.index = index
        self.length = length
        PacketError.__init__(
            self,
            'EAP-Message fragment %d (length %d): %s'
            % (index, length, reason))


class EAPStateError(PacketError):
    """The State of a request is not bound to its NAS session.

    Raised when a request presents a State this tracker never issued, or
    one issued for a different NAS or session. Answer the request with a
    deterministic Access-Reject; it must not enter the authentication
    state machine. The message deliberately names neither the State nor
    the session it is bound to.
    """

    def __init__(self):
        PacketError.__init__(self, 'State is not bound to this NAS session')


def packet_eap_fragments(pkt):
    """Return the EAP-Message fragments of a packet, in attribute order.

    Works with the attribute name when the dictionary of the packet
    defines EAP-Message, and with the raw attribute code otherwise.

    :param pkt: packet to read
    :type  pkt: pyrad.packet.Packet
    :return: the fragments, empty if the packet has no EAP-Message
    :rtype:  list[bytes]
    """
    values = pkt.get('EAP-Message') if pkt.dict is not None else None
    if values is None:
        values = pkt.get(EAP_MESSAGE, [])
    return [bytes(value) for value in values]


def packet_state(pkt):
    """Return the State of a packet, or None if it has none.

    :param pkt: packet to read
    :type  pkt: pyrad.packet.Packet
    :rtype:  bytes or None
    """
    values = pkt.get('State') if pkt.dict is not None else None
    if values is None:
        values = pkt.get(STATE, [])
    if not values:
        return None
    value = values[-1]
    if isinstance(value, str):
        # a 'string' attribute is decoded as UTF-8; encoding it again
        # returns the original octets
        value = value.encode('utf-8')
    return bytes(value)


class _EAPSession:
    """Reassembly state of one EAP conversation on one NAS."""

    def __init__(self):
        self.completed = deque(maxlen=COMPLETED_IDS)


class EAPSessionTracker:
    """Binds EAP-Message reassembly and State to NAS sessions.

    Sessions are keyed by ``(nas, session)``: use the NAS IP address or
    NAS-Identifier for ``nas`` and a session handle such as the
    User-Name, Called-Station-Id or Acct-Session-Id for ``session``.
    Fragments and State of concurrent NASes and sessions never mix.

    When a request passes :meth:`process`, the returned EAP packet is
    handed to the authenticator. When it raises, the request must not
    advance the authentication state machine: answer an
    :class:`EAPStateError` with a deterministic Access-Reject and drop
    or reject a request that raises :class:`EAPFragmentError`.
    """

    def __init__(self):
        self._states = {}
        self._sessions = {}

    def _session(self, nas, session):
        return self._sessions.setdefault((nas, session), _EAPSession())

    def bind_state(self, nas, session, state):
        """Bind a State to a NAS session.

        Call this with the State sent in an Access-Challenge of the
        session; a later request presenting it is only accepted from the
        same NAS session.

        :param nas: NAS the session belongs to
        :param session: session handle of the NAS
        :param state: State value sent to the NAS
        :type  state: bytes
        :raise ValueError: ``state`` is empty
        """
        state = bytes(state)
        if not state:
            raise ValueError('state must not be empty')
        self._states[state] = (nas, session)
        self._session(nas, session)

    def unbind_state(self, state):
        """Remove a State binding, e.g. when its session ends."""
        self._states.pop(bytes(state), None)

    def end_session(self, nas, session):
        """Drop a session and all State bound to it."""
        key = (nas, session)
        self._sessions.pop(key, None)
        for state, bound in list(self._states.items()):
            if bound == key:
                del self._states[state]

    def check_state(self, nas, session, state):
        """Check that a State is bound to this NAS session.

        :raise EAPStateError: the State is unknown or bound to another
                              NAS or session
        """
        if self._states.get(bytes(state)) != (nas, session):
            raise EAPStateError()

    def reassemble(self, nas, session, fragments):
        """Validate and join the EAP-Message fragments of one request.

        The fragments must be in attribute order and reassemble into
        exactly one complete EAP packet: no empty fragments, no missing
        or extra octets relative to the Length of the EAP header, and no
        retransmission of an already completed message.

        :param nas: NAS the request came from
        :param session: session handle of the NAS
        :param fragments: EAP-Message values in attribute order
        :type  fragments: list[bytes]
        :return: the complete EAP packet
        :rtype:  bytes
        :raise EAPFragmentError: the fragments do not form exactly one
                                 complete, fresh EAP packet
        """
        sess = self._session(nas, session)
        fragments = [bytes(fragment) for fragment in fragments]
        if not fragments:
            raise EAPFragmentError(0, 0, 'no fragments')

        first = fragments[0]
        if len(first) < EAP_HEADER_LENGTH:
            raise EAPFragmentError(
                0, len(first), 'shorter than the EAP header')
        declared = struct.unpack('!H', first[2:4])[0]
        if not EAP_HEADER_LENGTH <= declared <= MAX_EAP_MESSAGE_LENGTH:
            raise EAPFragmentError(0, len(first), 'invalid declared length')
        if first[1] in sess.completed:
            raise EAPFragmentError(
                0, len(first), 'retransmission of a completed message')

        total = 0
        for index, fragment in enumerate(fragments):
            if not fragment:
                raise EAPFragmentError(index, 0, 'empty fragment')
            total += len(fragment)
            if total > declared:
                raise EAPFragmentError(
                    index, len(fragment),
                    'message exceeds the declared length')
        if total < declared:
            raise EAPFragmentError(
                len(fragments) - 1, len(fragments[-1]),
                'message shorter than the declared length')

        sess.completed.append(first[1])
        return b''.join(fragments)

    def process(self, nas, session, fragments, state=None):
        """Check the State and reassemble the fragments of a request.

        The State is checked first: a request with an unknown or foreign
        State is rejected before its fragments are looked at, so it
        cannot disturb the reassembly of its own or another session.

        :param state: State of the request, if it has one
        :type  state: bytes or None
        :return: the complete EAP packet
        :rtype:  bytes
        :raise EAPStateError: see :meth:`check_state`
        :raise EAPFragmentError: see :meth:`reassemble`
        """
        if state is not None:
            self.check_state(nas, session, state)
        return self.reassemble(nas, session, fragments)

    def process_packet(self, nas, session, pkt):
        """Check the State and reassemble the EAP-Message of a packet.

        :param pkt: received Access-Request
        :type  pkt: pyrad.packet.Packet
        :return: the complete EAP packet, or None if the packet has no
                 EAP-Message
        :rtype:  bytes or None
        :raise EAPStateError: see :meth:`check_state`
        :raise EAPFragmentError: see :meth:`reassemble`
        """
        state = packet_state(pkt)
        if state is not None:
            self.check_state(nas, session, state)
        fragments = packet_eap_fragments(pkt)
        if not fragments:
            return None
        return self.reassemble(nas, session, fragments)
