History
#######

Unreleased
==========

- Add ``pcapng.manifest``: read-only sign-off manifest backend recording
  packet capture positions, resolved interface attribution and
  caller-trusted options into a recomputable digest, for verifying
  re-exported captures.

2.1.1
=====

- Fix deserialization of custom options

2.1.0
=====

- Use the explicit endianness everywhere when writing.

2.0.0
=====

- Write support

v0.1
====

- Support for "scanning" streams of pcap-ng data
- Support for decoding the "standard" pcap-ng blocks:

  - Section headers
  - Interface description
  - Enhanced packet
  - Simple packet (deprecated)
  - Packet (deprecated)
  - Name resolution
  - Interface statistics
