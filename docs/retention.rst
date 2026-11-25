Retention auditing (read-only)
================================

After a certificate migration, the responsible owner needs to know which JKS
private-key entries may be deleted, while the investigation side must keep the
public material required to verify historical signatures. The
:mod:`jks.retention` module produces that decision without ever modifying a
keystore.

Inputs are supplied entirely by the caller:

* the in-use window and retention window for each policy
  (:class:`~jks.retention.RetentionRule`);
* the externally held public-material archive
  (:class:`~jks.retention.PublicMaterialCatalog`);
* outstanding evidence work (:class:`~jks.retention.PendingItem`).

For every private-key entry, :func:`~jks.retention.audit_keystore` returns one
of three statuses:

* :data:`~jks.retention.RETAIN` - at least one rule still covers the entry in
  its in-use or retention window;
* :data:`~jks.retention.INSUFFICIENT_EVIDENCE` - every rule has expired but the
  public verification chain cannot be rebuilt from the external archive, or a
  pending item is unresolved;
* :data:`~jks.retention.DESTROY` - all rules have expired and the full public
  chain is reconstructable elsewhere.

Key invariants
--------------

* A duplicate certificate never compensates for a missing intermediate. The
  catalog deduplicates identical DER bytes, so adding another copy of a
  certificate that is already known does not close any chain gap.
* Incomplete evidence can never produce :data:`~jks.retention.DESTROY`. When a
  required certificate is missing, the result is always
  :data:`~jks.retention.INSUFFICIENT_EVIDENCE`.
* Chain reconstruction uses only public material held outside the keystore.
  Gaps are reported as :class:`~jks.retention.ChainGap` objects; blockers that
  can be lifted by archiving a specific known certificate expose its
  fingerprint through :attr:`~jks.retention.Blocker.resolvable_by`.

Example
-------

.. code-block:: python

    import datetime
    import jks
    from jks import retention as R

    keystore = jks.KeyStore.load("migrated.jks", "store-password")
    rules = [
        R.RetentionRule(
            "standard",
            in_use_until=datetime.datetime(2025, 6, 1),
            retain_until=datetime.datetime(2026, 1, 1)),
    ]
    catalog = R.PublicMaterialCatalog([root_cert_der, intermediate_cert_der])
    pending = [R.PendingItem("verify-leaf", fingerprint=leaf_fingerprint)]

    report = R.audit_keystore(
        keystore, rules, catalog, pending,
        now=datetime.datetime(2026, 6, 1))

    for alias, decision in report.decisions.items():
        print(alias, decision.status)
        for blocker in decision.blockers:
            print("  ", blocker.code, blocker.resolvable_by)

A fully synthetic, dependency-free end-to-end walkthrough lives in
``tools/retention_demo.py``. It builds an in-memory JKS, applies three
different retention rules, and shows that archiving one specific public
certificate removes a concrete blocker.
