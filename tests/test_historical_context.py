import base64
import json
import os
import unittest
import warnings
from contextlib import redirect_stdout
from io import StringIO

import LnkParse3
from LnkParse3.historical_context import build_historical_report
from LnkParse3.historical_context import HistoricalContext


SAMPLE = os.path.join(os.path.dirname(__file__), "samples", "extra_data")


def load_sample():
    with open(SAMPLE, "rb") as handle:
        return base64.b64decode(handle.read())


class TestHistoricalContext(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", category=UserWarning)
        self.indata = load_sample()

    def test_missing_variable_keeps_placeholder_and_lowers_certainty(self):
        context = HistoricalContext()
        record = context.resolve(r"C:\Users\%USERNAME%\AppData")

        self.assertEqual(record["certainty"], "unresolved")
        self.assertEqual(record["expanded"], r"C:\Users\%USERNAME%\AppData")
        self.assertEqual(record["raw"], r"C:\Users\%USERNAME%\AppData")
        self.assertEqual(record["placeholders"][0]["source"], "unresolved")
        self.assertIsNone(record["placeholders"][0]["value"])

    def test_partial_resolution_preserves_unknown_reference(self):
        context = HistoricalContext(system_variables={"USERNAME": "alice"})
        record = context.resolve(r"C:\Users\%USERNAME%\%APPNAME%\run.exe")

        self.assertEqual(record["certainty"], "partially_resolved")
        self.assertEqual(record["expanded"], r"C:\Users\alice\%APPNAME%\run.exe")
        sources = [item["source"] for item in record["placeholders"]]
        self.assertEqual(sources, ["system", "unresolved"])

    def test_resolved_and_no_placeholder_certainty(self):
        context = HistoricalContext(system_variables={"WINDIR": r"C:\Windows"})
        self.assertEqual(context.resolve(r"%WINDIR%\system32")["certainty"], "resolved")
        self.assertEqual(context.resolve(r"C:\plain\path")["certainty"], "no_placeholders")

    def test_conflict_system_first_selects_system_value(self):
        context = HistoricalContext(
            system_variables={"USERNAME": "machine-alice"},
            user_variables={"USERNAME": "profile-bob"},
            precedence="system_first",
        )
        record = context.resolve(r"C:\Users\%USERNAME%")

        self.assertEqual(record["expanded"], r"C:\Users\machine-alice")
        self.assertEqual(record["placeholders"][0]["source"], "system")

        conflict = context.conflict_report()[0]
        self.assertEqual(conflict["variable"], "USERNAME")
        self.assertEqual(conflict["system_value"], "machine-alice")
        self.assertEqual(conflict["user_value"], "profile-bob")
        self.assertEqual(conflict["selected_source"], "system")
        self.assertEqual(conflict["precedence"], "system_first")

    def test_conflict_user_first_selects_user_value(self):
        context = HistoricalContext(
            system_variables={"USERNAME": "machine-alice"},
            user_variables={"USERNAME": "profile-bob"},
            precedence="user_first",
        )
        record = context.resolve(r"C:\Users\%USERNAME%")

        self.assertEqual(record["expanded"], r"C:\Users\profile-bob")
        self.assertEqual(record["placeholders"][0]["source"], "user")
        self.assertEqual(context.conflict_report()[0]["selected_source"], "user")

    def test_variable_names_are_case_insensitive(self):
        context = HistoricalContext(system_variables={"username": "alice"})
        record = context.resolve(r"%UserName%")
        self.assertEqual(record["certainty"], "resolved")
        self.assertEqual(record["expanded"], "alice")
        self.assertEqual(record["placeholders"][0]["variable"], "USERNAME")

    def test_invalid_precedence_is_rejected(self):
        with self.assertRaises(ValueError):
            HistoricalContext(precedence="whoever")

    def test_same_sample_two_acquisition_identities_stay_distinct(self):
        operator = HistoricalContext(system_variables={"USERNAME": "examiner-on-duty-box"})
        alice = HistoricalContext(
            system_variables={"USERNAME": "alice"},
            user_variables={"USERNAME": "alice-profile"},
            precedence="system_first",
        )

        operator_report = build_historical_report(
            LnkParse3.lnk_file(indata=self.indata, historical_context=operator),
            operator,
        )
        alice_report = build_historical_report(
            LnkParse3.lnk_file(indata=self.indata, historical_context=alice),
            alice,
        )

        operator_block = operator_report["environment_variable_data_block"][0]
        alice_block = alice_report["environment_variable_data_block"][0]
        self.assertEqual(
            operator_block["expanded"],
            r"C:\Users\examiner-on-duty-box\AppData\Roaming\.minecraft",
        )
        self.assertEqual(
            alice_block["expanded"],
            r"C:\Users\alice\AppData\Roaming\.minecraft",
        )
        self.assertEqual(alice_block["placeholders"][0]["source"], "system")
        self.assertEqual(operator_block["raw"], alice_block["raw"])

    def test_live_machine_environment_never_feeds_resolution(self):
        os.environ["LNKPARSE3_TEST_VAR"] = "live-machine-value"
        try:
            context = HistoricalContext()
            record = context.resolve(r"%LNKPARSE3_TEST_VAR%")
            self.assertEqual(record["certainty"], "unresolved")
            self.assertEqual(record["expanded"], r"%LNKPARSE3_TEST_VAR%")
        finally:
            del os.environ["LNKPARSE3_TEST_VAR"]

    def test_report_sections_cover_string_data_and_environment_block(self):
        context = HistoricalContext(system_variables={"USERNAME": "alice"})
        lnk = LnkParse3.lnk_file(indata=self.indata, historical_context=context)
        report = lnk.historical_report()

        self.assertEqual([item["field"] for item in report["string_data"]], ["relative_path"])
        self.assertEqual(
            [item["field"] for item in report["environment_variable_data_block"]],
            ["target_ansi", "target_unicode"],
        )
        candidate_structures = {item["source_structure"] for item in report["candidates"]}
        self.assertEqual(candidate_structures, {"StringData", "EnvironmentVariableDataBlock"})

    def test_no_context_means_no_report_and_unchanged_json(self):
        lnk = LnkParse3.lnk_file(indata=self.indata)
        self.assertIsNone(lnk.historical_report())
        self.assertNotIn("historical_context", lnk.get_json())

    def test_dict_context_and_json_output(self):
        lnk = LnkParse3.lnk_file(
            indata=self.indata,
            historical_context={
                "system_variables": {"USERNAME": "alice"},
                "user_variables": {"USERNAME": "bob"},
                "precedence": "user_first",
            },
        )
        result = lnk.get_json()
        report = result["historical_context"]
        self.assertEqual(report["precedence"], "user_first")
        self.assertEqual(report["conflicts"][0]["selected_source"], "user")

        mock_stdout = StringIO()
        with redirect_stdout(mock_stdout):
            lnk.print_json()
        printed = json.loads(mock_stdout.getvalue())
        self.assertEqual(printed["historical_context"]["precedence"], "user_first")

    def test_invalid_context_type_is_rejected(self):
        with self.assertRaises(TypeError):
            LnkParse3.lnk_file(indata=self.indata, historical_context=42)


if __name__ == "__main__":
    unittest.main()
