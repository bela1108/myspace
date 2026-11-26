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

## Credential Reference Review

The optional offline review entry point reads signature-bearing original
Links and compares their public credential references and declared purposes
with an independent approval manifest. It does not execute build steps.

A missing `credential_refs` field means a legacy Link did not collect the
data. An explicit empty list means a new Link reports zero references. An
unsigned summary Link produces a separate missing-attestation result.

```{eval-rst}
.. autofunction:: in_toto.reviewlib.review_credential_approvals
```

```{eval-rst}
.. autofunction:: in_toto.reviewlib.review_layout
```

```{eval-rst}
.. autofunction:: in_toto.reviewlib.review_summary_link
```
