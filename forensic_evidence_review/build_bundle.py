"""Build the local STIX 2.1 bundle for the evidence comparison review.

Two signed "files match" reports share one short-text evidence item:

* Report FR-2023-0518 only retained an MD5 digest; its digital sample was
  never kept, so no strong digest can be recomputed for that exhibit.
* Report FR-2026-1112 retained the authorized digital sample and several
  digests; all digest values recorded here are recomputed locally from the
  sample inside the authorized window — none are fabricated.
"""

import base64
import hashlib
from pathlib import Path

import stix2

from custom_types import DigestCrossDateReview, HashCapabilityTable

HERE = Path(__file__).resolve().parent
SAMPLE_PATH = HERE / "evidence" / "statement-2023-0518.txt"
OUTPUT_PATH = HERE / "bundle" / "evidence-comparison-bundle.json"

LAB_ID = "identity--7f2e11a3-9b64-4d0b-8f2c-3a1d9e5b7c01"
TLP_RED_ID = stix2.TLP_RED.id
REL_TABLE_A_ID = "relationship--70000000-0000-4000-8000-000000000001"
REL_TABLE_B_ID = "relationship--70000000-0000-4000-8000-000000000002"
FILE_A_ID = "file--a1000000-0000-4000-8000-000000000001"
FILE_B_ID = "file--b1000000-0000-4000-8000-000000000002"
ARTIFACT_ID = "artifact--c1000000-0000-4000-8000-000000000003"
REPORT_A_ID = "report--10000000-0000-4000-8000-000000000001"
REPORT_B_ID = "report--10000000-0000-4000-8000-000000000002"
OBS_A_ID = "observed-data--20000000-0000-4000-8000-000000000001"
OBS_B_ID = "observed-data--20000000-0000-4000-8000-000000000002"
CAP_TABLE_ID = "x-hash-capability-table--30000000-0000-4000-8000-000000000001"
CROSS_REVIEW_ID = "x-digest-cross-date-review--40000000-0000-4000-8000-000000000001"
NOTE_ID = "note--50000000-0000-4000-8000-000000000001"
BUNDLE_ID = "bundle--60000000-0000-4000-8000-000000000001"

HISTORICAL_DATE = "2023-05-18"
HISTORICAL_TS = "2023-05-18T10:05:00Z"
RECOMPUTE_START = "2026-11-12T09:30:00Z"
RECOMPUTE_END = "2026-11-12T10:05:00Z"
REPORT_B_TS = "2026-11-12T15:20:00Z"
REVIEW_DATE = "2026-11-20"
REVIEW_TS = "2026-11-20T08:00:00Z"
RECOMPUTE_WINDOW = RECOMPUTE_START + "/" + RECOMPUTE_END


def recompute_digests(sample_bytes):
    """Recompute every cryptographic digest locally from the authorized sample."""
    return {
        "MD5": hashlib.md5(sample_bytes).hexdigest(),
        "SHA-1": hashlib.sha1(sample_bytes).hexdigest(),
        "SHA-256": hashlib.sha256(sample_bytes).hexdigest(),
        "SHA-512": hashlib.sha512(sample_bytes).hexdigest(),
    }


def build_observed_objects():
    sample_bytes = SAMPLE_PATH.read_bytes()
    b64 = base64.b64encode(sample_bytes).decode("ascii")
    recomputed = recompute_digests(sample_bytes)
    common_marking = [TLP_RED_ID]

    lab = stix2.v21.Identity(
        id=LAB_ID,
        created=REVIEW_TS, modified=REVIEW_TS,
        name="本地取证复核实验室（示例）",
        identity_class="organization",
        description="本地 STIX2 对象链路演示中的授权取证与复核单位。",
        object_marking_refs=common_marking,
    )
    file_a = stix2.v21.File(
        id=FILE_A_ID,
        name="statement-2023-0518.txt",
        hashes={"MD5": recomputed["MD5"]},
        allow_custom=True,
        custom_properties={
            "x_evidence_status": "原件未保留：FR-2023-0518 仅留存 MD5 旧摘要。",
        },
        object_marking_refs=common_marking,
    )
    sample_artifact = stix2.v21.Artifact(
        id=ARTIFACT_ID,
        mime_type="text/plain",
        payload_bin=b64,
        object_marking_refs=common_marking,
    )
    sample_file = stix2.v21.File(
        id=FILE_B_ID,
        name="statement-2023-0518.txt",
        size=len(sample_bytes),
        hashes=recomputed,
        content_ref=ARTIFACT_ID,
        allow_custom=True,
        custom_properties={
            "x_evidence_status": "授权保留的数字样品；全部摘要于 2026-11-12 从样品实际补算。",
        },
        object_marking_refs=common_marking,
    )
    objects = [stix2.TLP_RED, lab, file_a, sample_artifact, sample_file]
    return objects, recomputed, common_marking


def build_reports(objects, recomputed, common_marking):
    obs_a = stix2.v21.ObservedData(
        id=OBS_A_ID,
        created=HISTORICAL_TS, modified=HISTORICAL_TS,
        first_observed=HISTORICAL_TS, last_observed=HISTORICAL_TS,
        number_observed=1,
        object_refs=[FILE_A_ID],
        created_by_ref=LAB_ID,
        allow_custom=True,
        custom_properties={
            "x_record_summary": "FR-2023-0518 检验记录：仅留存 MD5 摘要，数字样品未归档。",
            "x_retained_artifacts": ["MD5"],
        },
        object_marking_refs=common_marking,
    )
    obs_b = stix2.v21.ObservedData(
        id=OBS_B_ID,
        created=REPORT_B_TS, modified=REPORT_B_TS,
        first_observed=RECOMPUTE_START, last_observed=RECOMPUTE_END,
        number_observed=1,
        object_refs=[FILE_B_ID, ARTIFACT_ID],
        created_by_ref=LAB_ID,
        allow_custom=True,
        custom_properties={
            "x_record_summary": "FR-2026-1112 检验记录：数字样品与多种摘要同时归档。",
            "x_retained_artifacts": ["数字样品(artifact payload)", "MD5", "SHA-1", "SHA-256", "SHA-512"],
        },
        object_marking_refs=common_marking,
    )
    report_a = stix2.v21.Report(
        id=REPORT_A_ID,
        created=HISTORICAL_TS, modified=HISTORICAL_TS,
        created_by_ref=LAB_ID,
        name="FR-2023-0518 电子数据检验报告（旧）",
        description=(
            "结论栏写着「文件吻合」。归档仅保留 MD5 旧摘要，数字样品未随案归档；"
            "2026-11-20 复核时无法取得原件。"
        ),
        report_types=["x-forensic-file-comparison"],
        published=HISTORICAL_TS,
        object_refs=[OBS_A_ID, FILE_A_ID],
        allow_custom=True,
        custom_properties={
            "x_retained_artifacts": ["MD5"],
            "x_missing_artifacts": ["数字样品原件", "SHA-1", "SHA-256", "SHA-512"],
            "x_signature_judgement": "2023-05-18 签字时按当时规程以 MD5 作同一性确认；历史判断保留可回查，复核日不再据此确认。",
        },
        object_marking_refs=common_marking,
    )
    report_b = stix2.v21.Report(
        id=REPORT_B_ID,
        created=REPORT_B_TS, modified=REPORT_B_TS,
        created_by_ref=LAB_ID,
        name="FR-2026-1112 电子数据检验报告（新）",
        description=(
            "结论栏同样写着「文件吻合」。归档保留授权数字样品与"
            "MD5/SHA-1/SHA-256/SHA-512 多种摘要，复核时可从样品实际补算。"
        ),
        report_types=["x-forensic-file-comparison"],
        published=REPORT_B_TS,
        object_refs=[OBS_B_ID, FILE_B_ID, ARTIFACT_ID],
        allow_custom=True,
        custom_properties={
            "x_retained_artifacts": ["数字样品(artifact payload)", "MD5", "SHA-1", "SHA-256", "SHA-512"],
            "x_missing_artifacts": [],
        },
        object_marking_refs=common_marking,
    )
    objects.extend([obs_a, obs_b, report_a, report_b])
    return objects, recomputed, common_marking


def build_capability_table(objects, recomputed, common_marking):
    entries = []
    entries.append({
        "entry_id": "CAP-A-MD5-2023",
        "report_ref": REPORT_A_ID,
        "algorithm": "MD5",
        "assessment_date": HISTORICAL_DATE,
        "capability": "confirm",
        "sample_available": False,
        "recomputed": False,
        "recomputation_window": "not_available_sample_never_retained",
        "basis_note": "2023-05-18 签字时 MD5 在该实验室规程下可用于同一性确认；历史判断保留可回查，无需原始样品即可复核当时结论。",
    })
    entries.append({
        "entry_id": "CAP-A-MD5-2026",
        "report_ref": REPORT_A_ID,
        "algorithm": "MD5",
        "assessment_date": REVIEW_DATE,
        "capability": "lead",
        "sample_available": False,
        "recomputed": False,
        "recomputation_window": "not_available_sample_never_retained",
        "basis_note": "2026-11-20 复核规程将 MD5 降为线索级；A 报告仅存旧 MD5，既不能单独确认，也因样品未保留而无法补算强算法。",
    })
    entries.append({
        "entry_id": "CAP-A-SHA1-2026",
        "report_ref": REPORT_A_ID,
        "algorithm": "SHA-1",
        "assessment_date": REVIEW_DATE,
        "capability": "lead",
        "sample_available": False,
        "recomputed": False,
        "recomputation_window": "not_available_sample_never_retained",
        "basis_note": "SHA-1 可构造碰撞，复核日仅作线索；A 档案没有 SHA-1 值也没有样品，无法补算，保持未得结论。",
    })
    entries.append({
        "entry_id": "CAP-A-SHA256-2026",
        "report_ref": REPORT_A_ID,
        "algorithm": "SHA-256",
        "assessment_date": REVIEW_DATE,
        "capability": "inconclusive",
        "sample_available": False,
        "recomputed": False,
        "recomputation_window": "not_available_sample_never_retained",
        "basis_note": "SHA-256 在复核日可用于确认，但 A 报告未保留数字样品，无法实际补算；没有原件时保留未得结论，不与 B 样品做强同一认定。",
    })
    entries.append({
        "entry_id": "CAP-A-SHA512-2026",
        "report_ref": REPORT_A_ID,
        "algorithm": "SHA-512",
        "assessment_date": REVIEW_DATE,
        "capability": "inconclusive",
        "sample_available": False,
        "recomputed": False,
        "recomputation_window": "not_available_sample_never_retained",
        "basis_note": "SHA-512 同属复核日可确认算法；A 档案缺原件，补算窗口从未开启，结论保持未得结论。",
    })
    entries.append({
        "entry_id": "CAP-A-SSDEEP-2026",
        "report_ref": REPORT_A_ID,
        "algorithm": "SSDEEP",
        "assessment_date": REVIEW_DATE,
        "capability": "inconclusive",
        "sample_available": False,
        "recomputed": False,
        "recomputation_window": "not_available_sample_never_retained",
        "recomputation_note": "工具版本无法对齐：A 档案无模糊哈希值、无样品，历史 ssdeep 版本亦未记录，无法在复核环境复现。",
        "basis_note": "版本无法对齐且缺原件，保留未得结论；即使日后取得样品，也需先固定与 2023 年一致的 ssdeep 版本才能回查。",
    })
    entries.append({
        "entry_id": "CAP-B-MD5-2023",
        "report_ref": REPORT_B_ID,
        "algorithm": "MD5",
        "assessment_date": HISTORICAL_DATE,
        "capability": "confirm",
        "sample_available": False,
        "recomputed": False,
        "recomputation_window": "not_applicable_report_not_yet_signed",
        "basis_note": "记录 2023-05-18 判定日的规程状态：当日 MD5 可用于确认；B 报告当时尚未签署，此条仅用于双日期对照。",
    })
    entries.append({
        "entry_id": "CAP-B-MD5-2026",
        "report_ref": REPORT_B_ID,
        "algorithm": "MD5",
        "assessment_date": REVIEW_DATE,
        "capability": "lead",
        "sample_available": True,
        "recomputed": True,
        "recomputation_window": RECOMPUTE_WINDOW,
        "recomputation_note": "已从授权样品实际补算 MD5，结果与 A 报告旧摘要一致；但复核日 MD5 只可作线索，确认须依赖 SHA-256。",
        "basis_note": "补算发生在样品授权期内；MD5 一致性支持两份报告指向同一短文本，但不单独构成确认。",
    })
    entries.append({
        "entry_id": "CAP-B-SHA1-2026",
        "report_ref": REPORT_B_ID,
        "algorithm": "SHA-1",
        "assessment_date": REVIEW_DATE,
        "capability": "lead",
        "sample_available": True,
        "recomputed": True,
        "recomputation_window": RECOMPUTE_WINDOW,
        "recomputation_note": "已从样品实际补算 SHA-1；因碰撞问题，复核规程将其列为线索级。",
        "basis_note": "补算值归档于 B 报告 observed-data，仅作线索使用。",
    })
    entries.append({
        "entry_id": "CAP-B-SHA256-2026",
        "report_ref": REPORT_B_ID,
        "algorithm": "SHA-256",
        "assessment_date": REVIEW_DATE,
        "capability": "confirm",
        "sample_available": True,
        "recomputed": True,
        "recomputation_window": RECOMPUTE_WINDOW,
        "recomputation_note": "已从授权样品实际补算 SHA-256：B 样品获得确认；A 因缺原件不能借此外推，其 SHA-256 项仍为未得结论。",
        "basis_note": "SHA-256 在复核规程下列为确认级；补算值与 B 档案值一致。",
    })
    entries.append({
        "entry_id": "CAP-B-SHA512-2026",
        "report_ref": REPORT_B_ID,
        "algorithm": "SHA-512",
        "assessment_date": REVIEW_DATE,
        "capability": "confirm",
        "sample_available": True,
        "recomputed": True,
        "recomputation_window": RECOMPUTE_WINDOW,
        "recomputation_note": "已从样品实际补算 SHA-512，与 B 档案值一致，作为 SHA-256 之外的第二确认算法交叉支撑。",
        "basis_note": "确认级算法；仅适用于仍持有样品的 B 报告。",
    })
    entries.append({
        "entry_id": "CAP-B-SSDEEP-2026",
        "report_ref": REPORT_B_ID,
        "algorithm": "SSDEEP",
        "assessment_date": REVIEW_DATE,
        "capability": "inconclusive",
        "sample_available": True,
        "recomputed": False,
        "recomputation_window": "blocked_version_alignment_pending",
        "recomputation_note": "样品在手，但复核环境 ssdeep 版本与 B 档案记录的历史版本无法对齐；版本固定前不做补算，避免产生不可比的模糊哈希。",
        "basis_note": "版本无法对齐时保留未得结论；属环境限制而非样品缺失，对齐版本后可在授权范围内补算。",
    })
    capability_table = HashCapabilityTable(
        id=CAP_TABLE_ID,
        created=REVIEW_TS, modified=REVIEW_TS,
        name="证物比对能力表：FR-2023-0518 / FR-2026-1112 双报告复核",
        description="按报告 × 算法 × 判定日期列明复核日可用于确认、仅可作线索或保留未得结论的能力，并标注是否已从授权样品实际补算、补算窗口及缺原件/版本不对齐的原因。",
        x_review_date=REVIEW_DATE,
        x_historical_judgment_date=HISTORICAL_DATE,
        x_algorithm_capability_entries=entries,
        x_report_refs=[REPORT_A_ID, REPORT_B_ID],
        x_evidence_refs=[FILE_A_ID, FILE_B_ID, ARTIFACT_ID],
        created_by_ref=LAB_ID,
        object_marking_refs=common_marking,
    )
    rel_table_a = stix2.v21.Relationship(
        id=REL_TABLE_A_ID,
        source_ref=CAP_TABLE_ID,
        relationship_type="derived-from",
        target_ref=REPORT_A_ID,
        description="能力表中 FR-2023-0518 条目派生自该历史报告及其留存的旧 MD5 摘要。",
        created=REVIEW_TS, modified=REVIEW_TS,
        created_by_ref=LAB_ID, object_marking_refs=common_marking, allow_custom=True,
    )
    rel_table_b = stix2.v21.Relationship(
        id=REL_TABLE_B_ID,
        source_ref=CAP_TABLE_ID,
        relationship_type="derived-from",
        target_ref=REPORT_B_ID,
        description="能力表中 FR-2026-1112 条目派生自该报告、数字样品及 2026-11-12 的实际补算记录。",
        created=REVIEW_TS, modified=REVIEW_TS,
        created_by_ref=LAB_ID, object_marking_refs=common_marking, allow_custom=True,
    )
    objects.extend([capability_table, rel_table_a, rel_table_b])
    return objects, recomputed, common_marking


def build_cross_date_review(objects, recomputed, common_marking):
    review_entries = [
        {
            "algorithm": "MD5",
            "digest_value": recomputed["MD5"],
            "historical_date": HISTORICAL_DATE,
            "historical_capability": "confirm",
            "review_date": REVIEW_DATE,
            "review_capability": "lead",
            "review_classification": "lead_only",
            "recomputed_from_sample": True,
            "original_available": True,
            "note": "同一短文本的同一枚 MD5：2023-05-18 可确认，2026-11-20 只能当线索；2026-11-12 已从 B 授权样品实际补算且与 A 旧摘要逐字一致，但 A 自身仍缺原件。",
        },
        {
            "algorithm": "SHA-1",
            "digest_value": recomputed["SHA-1"],
            "historical_date": HISTORICAL_DATE,
            "historical_capability": "not_recorded",
            "review_date": REVIEW_DATE,
            "review_capability": "lead",
            "review_classification": "lead_only",
            "recomputed_from_sample": True,
            "original_available": True,
            "note": "A 档案未记录 SHA-1；复核中已从 B 样品实际补算，按复核规程仅作线索，不能用于确认同一性。",
        },
        {
            "algorithm": "SHA-256",
            "digest_value": recomputed["SHA-256"],
            "historical_date": HISTORICAL_DATE,
            "historical_capability": "not_recorded",
            "review_date": REVIEW_DATE,
            "review_capability": "confirm",
            "review_classification": "recomputed",
            "recomputed_from_sample": True,
            "original_available": True,
            "note": "实际补算过的确认级摘要：B 样品经 SHA-256 补算后获得确认；A 报告缺原件，无法对 A 证物本身补算，该项对 A 保持未得结论。",
        },
    ]
    review_entries.append({
        "algorithm": "SHA-512",
        "digest_value": recomputed["SHA-512"],
        "historical_date": HISTORICAL_DATE,
        "historical_capability": "not_recorded",
        "review_date": REVIEW_DATE,
        "review_capability": "confirm",
        "review_classification": "recomputed",
        "recomputed_from_sample": True,
        "original_available": True,
        "note": "第二条实际补算过的确认级摘要，与 SHA-256 交叉支撑；同样只覆盖 B 样品，不外推到缺原件的 A 证物。",
    })
    review_entries.append({
        "algorithm": "SSDEEP",
        "digest_value": None,
        "historical_date": HISTORICAL_DATE,
        "historical_capability": "not_recorded",
        "review_date": REVIEW_DATE,
        "review_capability": "inconclusive",
        "review_classification": "missing_original_or_version",
        "recomputed_from_sample": False,
        "original_available": True,
        "note": "B 样品虽在，但 ssdeep 历史版本无法对齐，未实际补算；A 既无样品也无版本记录，该项整体保留未得结论。",
    })
    cross_review = DigestCrossDateReview(
        id=CROSS_REVIEW_ID,
        created=REVIEW_TS, modified=REVIEW_TS,
        name="同一短文本在两个判定日期的摘要对照复核",
        description="对 statement-2023-0518.txt 的每种摘要，并列 2023-05-18 与 2026-11-20 两个判定日期的能力，并注明仅作线索、已实际补算或缺原件/版本不对齐。",
        x_evidence_refs=[FILE_A_ID, FILE_B_ID, ARTIFACT_ID],
        x_report_refs=[REPORT_A_ID, REPORT_B_ID],
        x_capability_table_ref=CAP_TABLE_ID,
        x_short_text_ref=ARTIFACT_ID,
        x_historical_judgment_date=HISTORICAL_DATE,
        x_review_date=REVIEW_DATE,
        x_algorithm_date_entries=review_entries,
        created_by_ref=LAB_ID,
        allow_custom=True,
        object_marking_refs=common_marking,
    )
    objects.append(cross_review)
    return objects, recomputed, common_marking


def build_note(objects, recomputed, common_marking):
    note = stix2.v21.Note(
        id=NOTE_ID,
        created=REVIEW_TS, modified=REVIEW_TS,
        abstract="双报告证物比对复核结论（人工可读）",
        content=(
            "一、两份报告均表述为文件吻合。FR-2023-0518 仅留存旧 MD5 摘要、未保留数字样品；"
            "FR-2026-1112 同时保留数字样品与 MD5/SHA-1/SHA-256/SHA-512 多种摘要。\\n"
            "二、2023-05-18 签字时 MD5 按当时规程可用于确认，该历史判断仍可回查；2026-11-20 复核日 MD5、SHA-1 降为线索级，SHA-256、SHA-512 为确认级。\\n"
            "三、2026-11-12 已在授权窗口内从 B 样品实际补算四种摘要：MD5 与 A 旧摘要逐字一致（仅线索），SHA-256/SHA-512 对 B 样品构成确认，SHA-1 仅作线索。\\n"
            "四、A 报告缺原件，其 SHA-256/SHA-512/SSDEEP 均无法补算，保留未得结论；SSDEEP 因工具版本无法对齐，即使 B 有样品也未补算，整体未得结论。\\n"
            "五、对照标注口径：lead_only=只能当线索；recomputed=已实际补算；missing_original_or_version=缺原件或版本不对齐、保留未得结论。"
        ),
        object_refs=[CAP_TABLE_ID, CROSS_REVIEW_ID, REPORT_A_ID, REPORT_B_ID],
        created_by_ref=LAB_ID,
        allow_custom=True,
        object_marking_refs=common_marking,
    )
    objects.append(note)
    return objects, recomputed, common_marking


def main():
    objects, recomputed, common_marking = build_observed_objects()
    objects, recomputed, common_marking = build_reports(objects, recomputed, common_marking)
    objects, recomputed, common_marking = build_capability_table(objects, recomputed, common_marking)
    objects, recomputed, common_marking = build_cross_date_review(objects, recomputed, common_marking)
    objects, recomputed, common_marking = build_note(objects, recomputed, common_marking)
    bundle = stix2.v21.Bundle(objects=objects, id=BUNDLE_ID, allow_custom=True)
    serialized = bundle.serialize(pretty=True, ensure_ascii=False)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(serialized, encoding="utf-8")
    print("bundle written:", OUTPUT_PATH)
    print("objects:", len(bundle.objects))
    for algo, value in recomputed.items():
        print(f"recomputed {algo}: {value}")


if __name__ == "__main__":
    main()
