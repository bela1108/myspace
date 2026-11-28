==================
Testimony synthesis
==================

Downstream vulnerability management often receives two CPE Names for the
same device from different sources: a product inventory may report the
full version, while a device measurement only confirms the product but
contributes concrete platform attributes. The :mod:`cpe.cpesynthesis`
module merges such testimonies attribute by attribute.

Each source is wrapped in a :class:`Testimony` and the testimonies of a
device are merged with :meth:`SynthesisRecord.synthesize`::

    from cpe.cpesynthesis import SynthesisRecord, Testimony

    record = SynthesisRecord.synthesize("edge-router-01", [
        Testimony("inventory",
                  "cpe:2.3:h:acme:router_9000:4.2.1:sp2:*:*:*:*:*:*"),
        Testimony("measurement",
                  "cpe:2.3:h:acme:router_9000:*:*:*:*:*:*:armv7l:*"),
    ])

The record keeps a verdict per CPE attribute:

- ``agreed``: two or more sources assert the same value.
- ``complemented``: exactly one source asserts a value; the record adopts
  it and keeps its provenance.
- ``contested``: sources assert mutually exclusive values; the record
  keeps every value as a pending candidate instead of picking a winner.
- ``uninformed``: no source makes a claim about the attribute.

::

    record.verdict("version").value        # '4.2.1'
    record.verdict("version").provenance   # ('inventory',)
    record.verdict("target_hw").provenance # ('measurement',)
    record.as_cpe()  # merged CPE 2.3 formatted string

A contested conclusion needs an additional device record to be settled.
Given several synthesis records of a same-named device,
:func:`conclusions_needing_device_record` tells a risk system exactly
which conclusions are still unsettled::

    from cpe.cpesynthesis import conclusions_needing_device_record

    conclusions_needing_device_record([record1, record2, record3])
    # e.g. ['target_hw']
