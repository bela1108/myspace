Library usage
#############

Use the :py:class:`~pcapng.scanner.FileScanner` class to iterate over blocks
in a pcap-ng archive file, like this:

.. code-block:: python

    from pcapng import FileScanner

    with open('/tmp/mycapture.pcap') as fp:
        scanner = FileScanner(fp)
        for block in scanner:
            pass  # do something with the block...

Block types can be checked against blocks in :py:mod:`pcapng.blocks`.

Forensic pairing of two capture ends
####################################

When the same link was captured at both ends, the captures may use different
interfaces and snap lengths.  :func:`pcapng.pairing.pair_pcapng` consumes both
sources read-only and returns a :class:`pcapng.pairing.PairingReport`.

.. code-block:: python

    from pcapng.pairing import pair_pcapng

    report = pair_pcapng(
        "left.pcapng",
        "right.pcapng",
        left_direction="outbound",
        right_direction="inbound",
        max_time_delta=0.010,
    )

    for pair in report.pairs:
        print(pair.left.label, pair.right.label, pair.common_prefix_length)
        for truncation in pair.truncations:
            print(
                "truncated on",
                truncation.side,
                "at original byte",
                truncation.offset,
            )

The caller supplies both direction labels and a *finite* time window.  A pair
is emitted only when the two observations have the same original packet length,
agree over the whole shorter captured payload, and are the only compatible
candidate on both sides.  Otherwise the observations remain in
``report.unresolved``; many-to-one matches, repeated prefixes, and differing
captured payloads are never promoted merely because their headers match.
``report.ignored`` accounts for observations excluded by the direction filter.

Different capture lengths are handled by matching the complete shorter
observation against the longer common prefix.  If both sides are truncated at
different offsets, the pair is reported with both truncation offsets.  If both
stopped at exactly the same offset, only an identical prefix is visible and
the unobserved suffixes cannot be distinguished, so the observations stay
unresolved as ``unverified_truncated_suffix`` unless
``allow_identical_partial_pairing=True`` is explicitly requested.  For the
strictest review, ``require_complete_side=True`` requires at least one side to
have captured the complete original packet.
