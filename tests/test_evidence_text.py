import json
import unittest

from LnkParse3.evidence_text import Conclusion
from LnkParse3.evidence_text import SpanStatus
from LnkParse3.evidence_text import SupportMaterial
from LnkParse3.evidence_text import review_text_evidence


# 同一串路径字节：GBK 读作中文目录，cp1252 读作西欧字符，utf-8 直接失败。
GBK_PATH_BYTES = bytes.fromhex('c8edbcfe')
ASCII_PATH_BYTES = b'C:/Users/case'
GBK_TEXT = '软件'
GBK_RUN_TEXTS = ['软', '件']
CP1252_TAIL = '¼þ'


class TestTextEvidenceReview(unittest.TestCase):
    def test_unique_decoding_when_only_one_registered_encoding_succeeds(self):
        review = review_text_evidence(GBK_PATH_BYTES, ['gbk', 'utf-8'])

        self.assertEqual(review.conclusion, Conclusion.unique)
        self.assertEqual([r.encoding for r in review.valid_results], ['gbk'])
        self.assertEqual(review.valid_results[0].text, GBK_TEXT)

        failed = next(r for r in review.decoding_results if r.encoding == 'utf-8')
        self.assertFalse(failed.valid)
        self.assertEqual(failed.error_start, 0)

        # 每个读出的字符都绑回产生它的原始字节半开区间。
        self.assertEqual(
            [(run.start, run.end, run.text) for run in review.valid_results[0].runs],
            [(0, 2, GBK_RUN_TEXTS[0]), (2, 4, GBK_RUN_TEXTS[1])],
        )
        for span in review.span_reviews:
            self.assertEqual(span.status, SpanStatus.single_reading)
            self.assertEqual(set(span.readings), {'gbk'})

        payload = json.loads(json.dumps(review.to_dict(), ensure_ascii=False))
        self.assertEqual(payload['raw_hex'], GBK_PATH_BYTES.hex())
        self.assertEqual(payload['conclusion'], 'unique')

    def test_equivalent_when_different_encodings_yield_the_same_text(self):
        review = review_text_evidence(
            ASCII_PATH_BYTES, ['utf-8', 'gbk', 'cp1252']
        )

        self.assertEqual(review.conclusion, Conclusion.equivalent)
        self.assertEqual(len(review.valid_results), 3)
        self.assertEqual(review.distinct_texts, {'C:/Users/case'})

        # 三种编码按同一套字节区间对齐，逐区间读出相同文字。
        self.assertTrue(review.span_reviews)
        for span in review.span_reviews:
            self.assertEqual(span.status, SpanStatus.same_text)
            self.assertEqual(len(span.readings), 3)
            self.assertEqual(len(set(span.readings.values())), 1)

    def test_ambiguous_when_two_distinct_readings_remain(self):
        # 整段材料支持 GBK 读法：区间被收敛为 material_resolved，
        # 但 cp1252 的替代解释必须原样保留，结论仍是 ambiguous。
        full_material = SupportMaterial('EVID-GBK-01', 0, 4, GBK_TEXT)
        review = review_text_evidence(
            GBK_PATH_BYTES, ['gbk', 'cp1252', 'utf-8'], [full_material]
        )

        self.assertEqual(review.conclusion, Conclusion.ambiguous)
        self.assertEqual(review.distinct_texts, {GBK_TEXT, 'Èí¼þ'})

        gbk = next(r for r in review.decoding_results if r.encoding == 'gbk')
        cp1252 = next(r for r in review.decoding_results if r.encoding == 'cp1252')
        self.assertTrue(gbk.valid and cp1252.valid)
        # 不同解码绑回相同的原始字节区间（区间端点集合一致）。
        self.assertEqual(
            [(s.start, s.end) for s in review.span_reviews],
            [(0, 2), (2, 4)],
        )
        for span in review.span_reviews:
            self.assertEqual(span.status, SpanStatus.material_resolved)
            self.assertIn('gbk', span.readings)
            self.assertIn('cp1252', span.readings)
            self.assertTrue(any(f.supports for f in span.materials))
            self.assertEqual(span.materials[0].reference, 'EVID-GBK-01')

        # 材料只覆盖前半段时，后半段的歧义不得被这份材料抹掉。
        head_material = SupportMaterial(
            'EVID-GBK-HEAD', 0, 2, GBK_RUN_TEXTS[0]
        )
        partial = review_text_evidence(
            GBK_PATH_BYTES, ['gbk', 'cp1252'], [head_material]
        )
        self.assertEqual(partial.conclusion, Conclusion.ambiguous)
        head, tail = partial.span_reviews
        self.assertEqual(head.status, SpanStatus.material_resolved)
        self.assertEqual(tail.status, SpanStatus.contested)
        self.assertEqual(tail.materials, [])
        self.assertEqual(
            tail.readings,
            {'gbk': GBK_RUN_TEXTS[1], 'cp1252': CP1252_TAIL},
        )
        self.assertIn('[2,4)', partial.rationale)


if __name__ == '__main__':
    unittest.main()
