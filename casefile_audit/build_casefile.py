"""Builds the local STIX casefile (pre-correction) and the correction package.

Scenario
--------
* ``observed-data--E_A`` v1 records a wrong ``first_observed`` date
  (2026-01-05).  The correction package later issues v2 with the corrected
  date (2026-02-04).
* Three testimonies depend on the evidence, directly or through
  intermediate source statements:

  - T1 "证词甲": needs 2 independent sources, cites E_A@v1 + E_B.
  - T2 "证词乙": needs 2 independent sources, cites E_A@v1 + E_B + E_C
    (has a backup evidence path).
  - T3 "证词丙": needs 2 independent sources, cites S1 + S2, where S1 and
    S2 cite *each other* and only S1 reaches real evidence (E_D).

Outputs ``casefile.json`` (pre-correction bundle) and ``correction.json``
(the corrected v2 of E_A).
"""

import uuid

from stix2 import Bundle, ObservedData

from testimony import Testimony  # noqa: F401  (registers x-testimony)

NS = uuid.UUID("3f8b2c1e-7a4d-4e5f-9c6b-2d1a0e8f7b5c")


def oid(kind, name):
    return f"{kind}--{uuid.uuid5(NS, name)}"


E_A = oid("observed-data", "E_A")
E_B = oid("observed-data", "E_B")
E_C = oid("observed-data", "E_C")
E_D = oid("observed-data", "E_D")
T1 = oid("x-testimony", "T1")
T2 = oid("x-testimony", "T2")
T3 = oid("x-testimony", "T3")
S1 = oid("x-testimony", "S1")
S2 = oid("x-testimony", "S2")

EA_V1 = "2026-02-10T08:00:00.000Z"   # mistaken version of E_A
EA_V2 = "2026-03-01T09:00:00.000Z"   # corrected version of E_A


def observed(oid_, created, modified, first, last, note):
    return ObservedData(
        id=oid_,
        created=created,
        modified=modified,
        first_observed=first,
        last_observed=last,
        number_observed=1,
        objects={"0": {"type": "file", "name": note}},
        allow_custom=True,
    )


def testimony(oid_, statement, required, citations, ts):
    return Testimony(
        id=oid_,
        created=ts,
        modified=ts,
        statement=statement,
        required_independent_sources=required,
        citations=[{"source_ref": ref, "version": ver} for ref, ver in citations],
        allow_custom=True,
    )


def build():
    e_a_v1 = observed(E_A, EA_V1, EA_V1,
                      "2026-01-05T00:00:00Z", "2026-01-05T01:00:00Z",
                      "exhibit-A.evt  (early record, wrong date)")
    e_b = observed(E_B, "2026-02-12T08:00:00Z", "2026-02-12T08:00:00Z",
                   "2026-02-11T00:00:00Z", "2026-02-11T01:00:00Z",
                   "exhibit-B.evt")
    e_c = observed(E_C, "2026-02-15T08:00:00Z", "2026-02-15T08:00:00Z",
                   "2026-02-14T00:00:00Z", "2026-02-14T01:00:00Z",
                   "exhibit-C.evt")
    e_d = observed(E_D, "2026-02-20T08:00:00Z", "2026-02-20T08:00:00Z",
                   "2026-02-19T00:00:00Z", "2026-02-19T01:00:00Z",
                   "exhibit-D.evt")

    t1 = testimony(T1, "证词甲: 嫌疑人于 1 月初出现在现场",
                   2, [(E_A, EA_V1), (E_B, "2026-02-12T08:00:00Z")],
                   "2026-02-16T10:00:00Z")
    t2 = testimony(T2, "证词乙: 同一窗口期内有异常外传流量",
                   2, [(E_A, EA_V1),
                       (E_B, "2026-02-12T08:00:00Z"),
                       (E_C, "2026-02-15T08:00:00Z")],
                   "2026-02-17T10:00:00Z")
    s1 = testimony(S1, "来源陈述 S1: 转述现场值守记录",
                   1, [(E_D, "2026-02-20T08:00:00Z"),
                       (S2, "2026-02-21T10:00:00Z")],
                   "2026-02-21T09:00:00Z")
    s2 = testimony(S2, "来源陈述 S2: 转述 S1 的说法",
                   1, [(S1, "2026-02-21T09:00:00Z")],
                   "2026-02-21T10:00:00Z")
    t3 = testimony(T3, "证词丙: 值守期间门禁未被撬动",
                   2, [(S1, "2026-02-21T09:00:00Z"),
                       (S2, "2026-02-21T10:00:00Z")],
                   "2026-02-22T10:00:00Z")

    casefile = Bundle(e_a_v1, e_b, e_c, e_d, t1, t2, t3, s1, s2,
                      allow_custom=True)

    e_a_v2 = observed(E_A, EA_V1, EA_V2,
                      "2026-02-04T00:00:00Z", "2026-02-04T01:00:00Z",
                      "exhibit-A.evt  (corrected: first_observed 2026-02-04)")
    correction = Bundle(e_a_v2, allow_custom=True)

    with open("casefile.json", "w", encoding="utf-8") as f:
        f.write(casefile.serialize(pretty=True))
    with open("correction.json", "w", encoding="utf-8") as f:
        f.write(correction.serialize(pretty=True))
    print("wrote casefile.json and correction.json")


if __name__ == "__main__":
    build()
