Offline acceptance verifier
============================

An offline, chain-level verifier that sits on top of signedjson. The signing
backend already checks each Ed25519 signature individually; this package adds
the missing chain discipline: it follows the predecessor commitments and
decides which original material every event actually acknowledges.

Inputs
------
* A finite set of signed delivery events. Each event carries ``event_id``,
  ``signer``, ``material_id`` (the binding recorded in the main archive),
  ``material_digest`` (canonical sha256 of the original it was signed over),
  an optional ``predecessor`` event id, and signedjson ``signatures``.
* A material registry mapping ``sha256:<digest>`` to the original payload.
* A verify-key registry mapping each signer to its ``ed25519`` public key.

Rules
-----
* Every signature is re-verified offline against the key registry; unknown
  signers and bad signatures are rejected and never enter the chain.
* Re-delivery is detected both by event id and by a fingerprint of the
  signature block. The same signed acknowledgement can never advance the
  chain twice, even when the surrounding batch is replayed.
* Out-of-order delivery is harmless: decisions are recomputed from the whole
  admitted set, so an event stuck at ``awaiting_predecessor`` flips to
  ``confirmed`` once its predecessor is ingested in a later run.
* A fork is two or more validly signed events naming the same predecessor.
  The competing events are both retained with status ``fork`` for human
  review; their descendants stay on their own branch and are ``blocked``.
* A ``misbound`` event names a main-archive material that does not match the
  original its digest actually pins (or pins no registered original at all).
  Its descendants are ``blocked`` until a human reviews the binding.

Statuses
--------
``confirmed``, ``awaiting_predecessor``, ``fork``, ``misbound`` and
``blocked``. ``fork`` and ``misbound`` form the review queue
(``AcceptanceVerifier.review_queue``).

Persistence
-----------
``AcceptanceStore`` keeps events, materials, keys and the node summaries of
the most recent three runs (``SNAPSHOT_LIMIT = 3``). State is plain JSON, so
an air-gapped machine can reopen it and reconcile late predecessors.

CLI
---
::

    python -m signedjson.acceptance init --state state.json --keys keys.json --materials materials.json
    python -m signedjson.acceptance ingest --state state.json --events events.json
    python -m signedjson.acceptance snapshots --state state.json --latest

``ingest`` exits 3 when the review queue is non-empty unless ``--allow-review``
is passed.

See ``demo/offline_acceptance_demo.py`` for a self-contained four-run
scenario and ``tests/acceptance`` for the executable specification.
