"""End-to-end offline provenance review example.

Three feeds submit the same ``uses`` relationship.  Two of them merely
republish one original document, while the third cites a different one.  The
same claim set is evaluated against two source-independence policies to show
which relationship loses sufficient evidence.

Run with:  python examples/provenance_review.py
"""

from stix2.provenance import (
    Claim,
    IndependenceList,
    review_independence_lists,
)


USES = ("intrusion-set--apt-x", "uses", "tool--rat")

RELATIONSHIPS = [
    # Feed A and feed B both point at the same original document.
    Claim("relationship--feed-a", "report--feed-a", ("doc--acme-001",), USES),
    Claim("relationship--feed-b", "report--feed-b", ("doc--acme-001",), USES),
    # Feed C cites an independent document.
    Claim("relationship--feed-c", "report--feed-c", ("doc--ledger-077",), USES),
    # An extra record with no citation at all; it must be flagged separately.
    Claim(
        "relationship--no-source",
        "report--feed-d",
        (),
        ("intrusion-set--apt-x", "uses", "tool--dropper"),
    ),
]


def main():
    loose = IndependenceList(
        "loose policy: every cited document is its own source",
    )
    strict = IndependenceList(
        "strict policy: Acme and the Ledger share an editorial pipeline",
        source_groups=[["doc--acme-001", "doc--ledger-077"]],
    )

    review = review_independence_lists(RELATIONSHIPS, loose, strict)

    print("== baseline (%s) ==" % review.baseline.independence_list_name)
    print("retained conclusions:", review.baseline.retained)
    print("unattributed records:", review.baseline.unattributed)
    for key, conclusion in review.baseline.conclusions.items():
        print("  ", key, "->", conclusion.status.value,
              "independent sources:", conclusion.independent_source_count)

    print()
    print("== alternative (%s) ==" % review.alternative.independence_list_name)
    for key, conclusion in review.alternative.conclusions.items():
        print("  ", key, "->", conclusion.status.value,
              "independent sources:", conclusion.independent_source_count)

    print()
    print("relationships that lost sufficient evidence:", review.lost_support)
    print("relationships that gained sufficient evidence:", review.gained_support)


if __name__ == "__main__":
    main()
