# API

The in-toto API provides various functions and {doc}`classes <model>` that you
can use to generate, consume, modify and verify in-toto metadata, as a more
feature-rich, programmable alternative to the {doc}`command line tools
<command-line-tools/index>`.

```{admonition} Cryptographic Signatures
:class: tip

in-toto metadata is signed with cryptographic keys via the *Signer API*
in [securesystemslib](https://github.com/secure-systems-lab/securesystemslib)
Please refer to its [documentation](https://python-securesystemslib.readthedocs.io/en/latest/signer.html)
for details about loading a `Signer` for "Evidence Generation".

Loading verification keys for "Supply Chain Verification" is
documented [in-toto#663](https://github.com/in-toto/in-toto/issues/663).
```

## Evidence Generation

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_run
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_record_start
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_record_stop
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_match_products

```

### Material Resolution Evidence

Material recording can return an ``EvidenceReport`` that keeps the digest, the
source that was read, and the source identity observed before and after the
read. Entries that cannot prove a stable source are marked ``unverified``;
entries whose source changed during the read are marked ``changed`` and can be
looked up together with the resolver that produced them.

```{eval-rst}
.. autofunction:: in_toto.runlib.record_artifacts_with_evidence
```

```{eval-rst}
.. autoclass:: in_toto.resolver.evidence.EvidenceReport
   :members:
```

```{eval-rst}
.. autoclass:: in_toto.resolver.evidence.EvidenceEntry
   :members:
```

## Supply Chain Verification

```{eval-rst}
.. autofunction:: in_toto.verifylib.in_toto_verify
```
