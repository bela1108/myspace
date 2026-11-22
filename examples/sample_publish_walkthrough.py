"""
Walkthrough publishing two sample documents which share one rich-text
block, leaving behind ``cache_records.json`` with one record per publish
call.

The scenario exercises the three cache trajectories:

* ``revoked`` -- the legal attachment's pinned rule version is revoked,
  so its previously cached block is invalidated and recomputed under the
  current authorized version.
* ``unchanged`` -- the knowledge base article's block is untouched by
  that revocation and is served from the cache.
* ``ancestor_changed`` -- the knowledge base article is moved to a
  section pinned to a newer rule version, forcing a recompute.

Run from the repository root:

    python examples/sample_publish_walkthrough.py
"""

import json
from pathlib import Path

from html_sanitizer.publish import (
    KNOWLEDGE_BASE,
    LEGAL_ATTACHMENT,
    Block,
    BlockPublishCache,
    Document,
    RuleRegistry,
    Section,
)


def rule_settings(tags):
    return {
        "tags": set(tags),
        "empty": set(),
        "separate": {"p"},
        "whitespace": set(),
        "attributes": {},
    }


def build_registry():
    registry = RuleRegistry()
    # Legal attachments: v1 kept <em> out, v2 allows it again.
    registry.register(LEGAL_ATTACHMENT, "legal-v1", rule_settings({"p", "strong"}))
    registry.register(
        LEGAL_ATTACHMENT, "legal-v2", rule_settings({"p", "strong", "em"})
    )
    # Knowledge base: v2 adds <strong> on top of v1.
    registry.register(KNOWLEDGE_BASE, "kb-v1", rule_settings({"p", "em"}))
    registry.register(KNOWLEDGE_BASE, "kb-v2", rule_settings({"p", "em", "strong"}))
    return registry


# The two sample documents and the rich-text block they both reference.
SHARED_BLOCK = Block("block-shared-001", "<p>Hello <em>there</em> <strong>all</strong></p>")

LEGAL_DOC_V1 = Document(
    "doc-legal-001", LEGAL_ATTACHMENT, Section("sec-legal-old", "legal-v1")
)
KB_DOC_V1 = Document("doc-kb-002", KNOWLEDGE_BASE, Section("sec-kb-old", "kb-v1"))
KB_DOC_V2 = Document("doc-kb-002", KNOWLEDGE_BASE, Section("sec-kb-new", "kb-v2"))


def main():
    registry = build_registry()
    cache = BlockPublishCache(registry)
    steps = []

    def publish(document, note):
        html, event = cache.publish(document, SHARED_BLOCK)
        steps.append({**event.as_dict(), "note": note, "html": html})
        return html

    publish(LEGAL_DOC_V1, "legal attachment first publish (cold)")
    publish(LEGAL_DOC_V1, "legal attachment republished unchanged (hit)")
    publish(KB_DOC_V1, "knowledge base first publish of the shared block (cold)")

    # Historical rule version revoked: the legal cache entry must die.
    registry.revoke(LEGAL_ATTACHMENT, "legal-v1")
    publish(LEGAL_DOC_V1, "legal-v1 revoked, block recomputed under legal-v2")

    # The knowledge base entry is unaffected by the legal revocation.
    publish(KB_DOC_V1, "knowledge base unaffected by legal revocation (hit)")

    # The article moves to a section pinned to a newer rule version.
    publish(KB_DOC_V2, "ancestor section changed kb-v1 -> kb-v2 (recompute)")

    out = Path(__file__).with_name("cache_records.json")
    out.write_text(
        json.dumps({"steps": steps}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    for step in steps:
        print(
            f"#{step['seq']} {step['doc_id']} {step['outcome']:<10}"
            f" {step['reason']:<18} -> {step['html']}"
        )
    print(f"records written to {out}")


if __name__ == "__main__":
    main()
