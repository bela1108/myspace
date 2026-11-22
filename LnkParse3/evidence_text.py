"""
离线文字证物审查。

历史快捷方式等检材中的路径文字，在进入案卷前可能经过不同区域的取证
工作站，同一串原始字节在不同字符编码下会被读出不同的目录文字。本模块
只对已经采集到的原始字节做事后审查，不联网、不猜测未登记的编码。

审查输入有三样：

* ``raw``：检材中提取出来的原始字段字节；
* ``encodings``：采集人登记的、本检材允许使用的合法字符编码清单；
* ``materials``：可以回查的支持材料（如镜像快照、注册表备份、现场记录
  编号），每份材料只对它覆盖到的字节区间和文字主张负责。

核心约束：

* 每一种编码读出来的每个字符，都绑回产生它的原始字节半开区间
  ``[start, end)``，不同解码之间按同一套字节区间对齐展示；
* 一份支持材料只能佐证或反驳它覆盖区间内的读法，不能抹掉它没有覆盖
  到的字节上的歧义；
* 即使某种解释被材料支持，其它解释仍然原样保留在结果里，由区间级
  状态标明哪些字节已经收敛、哪些字节仍然存在分歧。
"""

import codecs
from dataclasses import dataclass
from dataclasses import field
from enum import Enum


class Conclusion(str, Enum):
    """整段字段的审查结论。"""

    unique = 'unique'
    equivalent = 'equivalent'
    ambiguous = 'ambiguous'
    inconclusive = 'inconclusive'


class SpanStatus(str, Enum):
    """单个字节区间的收敛状态。"""

    single_reading = 'single_reading'
    same_text = 'same_text'
    contested = 'contested'
    material_resolved = 'material_resolved'
    unreadable = 'unreadable'


@dataclass
class ByteSpan:
    """原始字节上的半开区间 [start, end)。"""

    start: int
    end: int

    @property
    def width(self):
        return self.end - self.start

    def covers(self, other):
        return self.start <= other.start and other.end <= self.end


@dataclass
class DecodedRun:
    """一次成功解码出的单个字符及其原始字节区间。"""

    start: int
    end: int
    text: str

    @property
    def span(self):
        return ByteSpan(self.start, self.end)


@dataclass
class EncodingResult:
    """单个登记编码对整段字段的审查结果。"""

    encoding: str
    valid: bool
    runs: list = field(default_factory=list)
    text: str = ''
    error_start: int = None
    error_end: int = None
    error_reason: str = None

    def reading_at(self, span):
        """返回该编码在给定区间内读出的文字；区间未被完整解码时为 None。"""
        pieces = []
        covered = 0
        for run in self.runs:
            if run.start < span.start or run.end > span.end:
                continue
            pieces.append(run.text)
            covered += run.end - run.start
        if covered != span.width:
            return None
        return ''.join(pieces)


@dataclass
class SupportMaterial:
    """一份可回查的支持材料。

    start/end 为材料覆盖的原始字节半开区间；expected_text 是材料中登记
    的该区间应当读出的文字；reference 是回查线索（材料编号、快照偏移
    等），必须随结果保留。
    """

    reference: str
    start: int
    end: int
    expected_text: str

    @property
    def span(self):
        return ByteSpan(self.start, self.end)


@dataclass
class MaterialFinding:
    """一份材料针对某条区间读法的核验结论。"""

    reference: str
    expected_text: str
    supports: bool
    contradicts: bool


@dataclass
class SpanReview:
    """一个字节区间在所有登记编码下的对齐审查结果。"""

    start: int
    end: int
    status: SpanStatus
    readings: dict = field(default_factory=dict)
    materials: list = field(default_factory=list)


@dataclass
class TextEvidenceReview:
    """整段原始字段的离线审查结果。"""

    raw: bytes
    encodings: list
    decoding_results: list = field(default_factory=list)
    span_reviews: list = field(default_factory=list)
    conclusion: Conclusion = None
    rationale: str = ''

    @property
    def valid_results(self):
        return [result for result in self.decoding_results if result.valid]

    @property
    def distinct_texts(self):
        return {result.text for result in self.valid_results}

    @property
    def unresolved_spans(self):
        return [
            span for span in self.span_reviews
            if span.status in (SpanStatus.contested, SpanStatus.unreadable)
        ]

    def to_dict(self):
        """生成可直接序列化进案卷的纯数据结构（字节以十六进制表示）。"""
        return {
            'raw_hex': self.raw.hex(),
            'raw_length': len(self.raw),
            'encodings': list(self.encodings),
            'conclusion': self.conclusion.value,
            'rationale': self.rationale,
            'decoding_results': [
                {
                    'encoding': result.encoding,
                    'valid': result.valid,
                    'text': result.text,
                    'runs': [
                        {'start': run.start, 'end': run.end, 'text': run.text}
                        for run in result.runs
                    ],
                    'error': None if result.valid else {
                        'start': result.error_start,
                        'end': result.error_end,
                        'reason': result.error_reason,
                    },
                }
                for result in self.decoding_results
            ],
            'span_reviews': [
                {
                    'start': span.start,
                    'end': span.end,
                    'status': span.status.value,
                    'readings': dict(span.readings),
                    'materials': [
                        {
                            'reference': finding.reference,
                            'expected_text': finding.expected_text,
                            'supports': finding.supports,
                            'contradicts': finding.contradicts,
                        }
                        for finding in span.materials
                    ],
                }
                for span in self.span_reviews
            ],
        }


def review_text_evidence(raw, encodings, materials=None):
    """对原始字段字节执行离线文字证物审查。

    :param bytes raw: 检材中的原始字段字节。
    :param encodings: 采集人登记的合法字符编码，按登记顺序去重。
    :param materials: :class:`SupportMaterial` 列表，可为空。
    :rtype: TextEvidenceReview
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError('raw 必须是原始字节 (bytes/bytearray)')
    raw = bytes(raw)

    registered = _deduplicate(encodings)
    if not registered:
        raise ValueError('至少需要登记一个合法字符编码')

    material_list = list(materials or [])
    _validate_materials(material_list, len(raw))

    decoding_results = [_decode_with_spans(raw, encoding) for encoding in registered]
    span_reviews = _review_spans(decoding_results, material_list)
    conclusion, rationale = _conclude(decoding_results, span_reviews)

    return TextEvidenceReview(
        raw=raw,
        encodings=registered,
        decoding_results=decoding_results,
        span_reviews=span_reviews,
        conclusion=conclusion,
        rationale=rationale,
    )


def _deduplicate(encodings):
    seen = set()
    ordered = []
    for encoding in encodings:
        if encoding not in seen:
            seen.add(encoding)
            ordered.append(encoding)
    return ordered


def _validate_materials(materials, raw_length):
    for material in materials:
        if not isinstance(material, SupportMaterial):
            raise TypeError('支持材料必须是 SupportMaterial 实例')
        if not 0 <= material.start < material.end <= raw_length:
            raise ValueError(
                f'材料 {material.reference!r} 的字节区间 '
                f'[{material.start}, {material.end}) 超出原始字段范围'
            )
        if not material.reference:
            raise ValueError('支持材料必须带有可回查的 reference')


def _decode_with_spans(raw, encoding):
    """逐字节喂入增量解码器，把每个产出字符绑回原始字节区间。"""
    result = EncodingResult(encoding=encoding, valid=True)

    try:
        raw.decode(encoding)
    except UnicodeDecodeError as error:
        result.valid = False
        result.error_start = error.start
        result.error_end = error.end
        result.error_reason = error.reason
    except LookupError as error:
        result.valid = False
        result.error_start = 0
        result.error_end = len(raw)
        result.error_reason = str(error)
        return result

    try:
        decoder = codecs.getincrementaldecoder(encoding)()
    except LookupError as error:
        result.valid = False
        result.error_reason = str(error)
        return result

    runs = []
    run_start = 0
    for index in range(1, len(raw) + 1):
        try:
            piece = decoder.decode(raw[index - 1:index])
        except UnicodeDecodeError as error:
            result.valid = False
            if result.error_start is None:
                result.error_start = run_start + error.start
                result.error_end = run_start + error.end
                result.error_reason = error.reason
            break
        if piece:
            runs.append(DecodedRun(start=run_start, end=index, text=piece))
            run_start = index
    else:
        try:
            tail = decoder.decode(b'', final=True)
        except UnicodeDecodeError as error:
            result.valid = False
            if result.error_start is None:
                result.error_start = run_start + error.start
                result.error_end = run_start + error.end
                result.error_reason = error.reason
            tail = ''
        if tail:
            runs.append(DecodedRun(start=run_start, end=len(raw), text=tail))

    result.runs = runs
    result.text = ''.join(run.text for run in runs)
    return result


def _collect_boundaries(decoding_results, materials, raw_length):
    boundaries = {0, raw_length}
    for result in decoding_results:
        if not result.valid:
            if result.error_start is not None:
                boundaries.add(result.error_start)
                boundaries.add(min(result.error_end, raw_length))
            continue
        for run in result.runs:
            boundaries.add(run.start)
            boundaries.add(run.end)
    for material in materials:
        boundaries.add(material.start)
        boundaries.add(material.end)
    return boundaries


def _aligned_cuts(boundaries, decoding_results, raw_length):
    """把切分点对齐到各编码的解码 run 边界。

    多字节编码里一个字符由多个字节共同产生，切分点不能落在字符中间，
    否则该编码在子区间上将无法回读。任何会切进某条 run 的候选边界都
    回退到该 run 的起点，保证每个区间对所有编码都是可回读的原子区间。
    """
    cuts = sorted(boundaries)
    aligned = [0]
    for point in cuts[1:]:
        adjusted = point
        for result in decoding_results:
            if not result.valid:
                continue
            for run in result.runs:
                if run.start < point < run.end:
                    adjusted = min(adjusted, run.start)
        adjusted = max(aligned[-1], min(adjusted, raw_length))
        if adjusted > aligned[-1]:
            aligned.append(adjusted)
    if aligned[-1] != raw_length:
        aligned.append(raw_length)
    return list(zip(aligned, aligned[1:]))


def _evaluate_materials(decoding_results, materials):
    """按材料登记的完整区间核验各编码，返回 reference -> MaterialFinding。

    一份材料主张某字节区间应读出某段文字；核验时取每个合法编码在该
    区间上的完整读法与之比对。材料覆盖多个对齐区间时，同一条核验结论
    会下放到它覆盖的每个区间，但材料本身只对登记区间负责。
    """
    findings_by_ref = {}
    for material in materials:
        readings = {}
        for result in decoding_results:
            if not result.valid:
                continue
            reading = result.reading_at(material.span)
            if reading is not None:
                readings[result.encoding] = reading
        supports = material.expected_text in readings.values()
        findings_by_ref[material.reference] = MaterialFinding(
            reference=material.reference,
            expected_text=material.expected_text,
            supports=supports,
            contradicts=bool(readings) and not supports,
        )
    return findings_by_ref


def _review_spans(decoding_results, materials):
    raw_length = max(
        [run.end for result in decoding_results for run in result.runs]
        + [result.error_end or 0 for result in decoding_results]
        + [material.end for material in materials]
        + [0]
    )
    boundaries = _collect_boundaries(decoding_results, materials, raw_length)
    cuts = _aligned_cuts(boundaries, decoding_results, raw_length)
    findings_by_ref = _evaluate_materials(decoding_results, materials)

    reviews = []
    for start, end in cuts:
        span = ByteSpan(start, end)
        readings = {}
        for result in decoding_results:
            if not result.valid:
                continue
            reading = result.reading_at(span)
            if reading is not None:
                readings[result.encoding] = reading

        findings = []
        for material in materials:
            if material.span.covers(span):
                findings.append(findings_by_ref[material.reference])
        status = _span_status(decoding_results, readings, findings)
        reviews.append(
            SpanReview(
                start=start,
                end=end,
                status=status,
                readings=readings,
                materials=findings,
            )
        )
    return reviews


def _span_status(decoding_results, readings, findings):
    valid_here = [
        result for result in decoding_results
        if result.valid and result.encoding in readings
    ]
    if not valid_here:
        return SpanStatus.unreadable

    distinct = set(readings.values())
    if len(distinct) == 1:
        if len(valid_here) == 1:
            return SpanStatus.single_reading
        return SpanStatus.same_text

    supported_texts = {
        finding.expected_text for finding in findings if finding.supports
    }
    if len(supported_texts) == 1:
        return SpanStatus.material_resolved
    return SpanStatus.contested


def _conclude(decoding_results, span_reviews):
    valid_results = [result for result in decoding_results if result.valid]
    if not valid_results:
        return (
            Conclusion.inconclusive,
            '登记的编码均无法完整解码该字段，没有任何可读解释可供采纳',
        )

    distinct_texts = {result.text for result in valid_results}
    if len(valid_results) == 1:
        encoding = valid_results[0].encoding
        return (
            Conclusion.unique,
            f'只有登记编码 {encoding!r} 能完整解码，得到唯一解释',
        )

    if len(distinct_texts) == 1:
        names = ', '.join(result.encoding for result in valid_results)
        return (
            Conclusion.equivalent,
            f'多个登记编码（{names}）读出完全相同的文字，编码层面有别但文字唯一',
        )

    unresolved = [
        span for span in span_reviews
        if span.status in (SpanStatus.contested, SpanStatus.unreadable)
    ]
    if unresolved:
        intervals = ', '.join(f'[{span.start},{span.end})' for span in unresolved)
        return (
            Conclusion.ambiguous,
            f'存在两种以上不同解释，且字节区间 {intervals} 仍未被支持材料收敛',
        )

    return (
        Conclusion.ambiguous,
        '整段存在两种不同解释；各分歧区间均被支持材料收敛，但替代解释仍保留在结果中',
    )
