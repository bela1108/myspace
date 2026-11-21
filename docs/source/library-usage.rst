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

Before writing an archive for a downstream parser with partial block support,
use :py:func:`pcapng.preflight_exchange`:

.. code-block:: python

    from pcapng import DiscardPolicy, ReceiverCapabilities, preflight_exchange

    receiver = ReceiverCapabilities(
        ("SHB", "IDB", "EPB"),
        allow_unknown_blocks=True,
        name="packet-reader",
    )
    report = preflight_exchange(
        source_bytes,
        receiver,
        DiscardPolicy(discardable_block_types=("ISB",)),
    )

    if report.exchangeable:
        output_bytes = report.to_bytes()

The report distinguishes :attr:`~pcapng.exchange.ExchangeReport.kept_blocks`,
:attr:`~pcapng.exchange.ExchangeReport.skippable_extensions`,
:attr:`~pcapng.exchange.ExchangeReport.dropped_blocks` and
:attr:`~pcapng.exchange.ExchangeReport.required_unknown`.  Evidence loss is
reported separately through
:attr:`~pcapng.exchange.ExchangeReport.evidence_loss` and
:attr:`~pcapng.exchange.ExchangeReport.affected_interface_scopes`.
