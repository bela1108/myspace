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

## Supply Chain Verification

```{eval-rst}
.. autofunction:: in_toto.verifylib.in_toto_verify
```

### Offline Rework Verification

When an intermediate product is reworked after downstream spot-checks were
already performed on the original product, the following helpers decide from
signed link metadata which evidence still carries over and which
responsibility is reactivated.  The decision combines material identity, the
rework completion time and the replacement types authorized by each
inspection.

```{eval-rst}
.. autoclass:: in_toto.reworklib.ArtifactChange
   :members:
```

```{eval-rst}
.. autoclass:: in_toto.reworklib.ReplacementType
   :members:
```

```{eval-rst}
.. autoclass:: in_toto.reworklib.InspectionStatus
   :members:
```

```{eval-rst}
.. autoclass:: in_toto.reworklib.InspectionRecord
   :members:
```

```{eval-rst}
.. autoclass:: in_toto.reworklib.ReworkVerificationReport
   :members:
```

```{eval-rst}
.. autofunction:: in_toto.reworklib.classify_artifacts
```

```{eval-rst}
.. autofunction:: in_toto.reworklib.verify_rework
```
