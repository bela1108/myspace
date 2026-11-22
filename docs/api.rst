API reference
=============

Encoding
--------

.. autofunction:: cbor2.dumps
.. autofunction:: cbor2.dump
.. autoclass:: cbor2.CBOREncoder
.. autodecorator:: cbor2.shareable_encoder

Decoding
--------

.. autofunction:: cbor2.loads
.. autofunction:: cbor2.load
.. autoclass:: cbor2.CBORDecoder
.. autodecorator:: cbor2.shareable_decoder

Multi-bundle references
-----------------------

.. autofunction:: cbor2.load_bundle
.. autofunction:: cbor2.loads_bundle
.. autofunction:: cbor2.parse_bundle
.. autofunction:: cbor2.dumps_bundle
.. autofunction:: cbor2.dump_bundle
.. autofunction:: cbor2.public_index
.. autofunction:: cbor2.handover_check
.. autofunction:: cbor2.resolve_reference
.. autofunction:: cbor2.build_checklist
.. autofunction:: cbor2.reference_tag_hook
.. autofunction:: cbor2.reference_semantic_decoders
.. autodata:: cbor2.LOCAL_REF_TAG
.. autodata:: cbor2.CROSS_REF_TAG
.. autoclass:: cbor2.Bundle
.. autoclass:: cbor2.EntryDescriptor
.. autoclass:: cbor2.Reference
.. autoclass:: cbor2.ReferenceKind
.. autoclass:: cbor2.ReferenceStatus
.. autoclass:: cbor2.EvidencePermissions
.. autoclass:: cbor2.ChecklistItem
.. autoclass:: cbor2.Conclusion
.. autoclass:: cbor2.AuditReport

Types
-----

.. autoclass:: cbor2.CBORSimpleValue
.. autoclass:: cbor2.CBORTag
.. autoclass:: cbor2.frozendict
.. data:: cbor2.undefined

    A singleton representing the CBOR "undefined" value.

Type aliases
------------

.. type:: SemanticDecoderCallback
    :canonical: ~collections.abc.Callable[[Any, bool], Any]

    The common type of callbacks accepted in the ``semantic_decoders`` decoder option.
.. type:: ShareableDecoderInitializer
    :canonical: ~collections.abc.Callable[[bool], tuple[Any, ShareableDecoderCallback]]

    A two-phase decoder callback accepted in the ``semantic_decoders`` decoder option.
.. type:: ShareableDecoderCallback
    :canonical: ~collections.abc.Callable[[Any], Any]

    Type of the callback returned by a :type:`ShareableDecoderInitializer`
.. type:: ObjectHook
    :canonical: ~collections.abc.Callable[[collections.abc.Mapping[Any, Any]], Any]

    Type of the callback needed for the ``object_hook`` decoder option.
.. type:: TagHook
    :canonical: ~collections.abc.Callable[[CBORTag], Any]

    Type of the callback needed for the ``tag_hook`` decoder option.
.. type:: EncoderHook
    :canonical: ~collections.abc.Callable[[CBOREncoder, Any], Any]

    Type of the callback needed for the ``default`` encoder option.

Exceptions
----------

.. autoexception:: cbor2.CBORError
.. autoexception:: cbor2.CBOREncodeError
.. autoexception:: cbor2.CBOREncodeTypeError
.. autoexception:: cbor2.CBOREncodeValueError
.. autoexception:: cbor2.CBORDecodeError
.. autoexception:: cbor2.CBORDecodeEOF
