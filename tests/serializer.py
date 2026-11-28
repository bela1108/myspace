#!/usr/bin/env python3
"""Tests for the date and time values serializer."""

import json
import unittest

from dfdatetime import dotnet_datetime
from dfdatetime import fat_date_time
from dfdatetime import golang_time
from dfdatetime import posix_time
from dfdatetime import rfc2579_date_time
from dfdatetime import semantic_time
from dfdatetime import serializer
from dfdatetime import systemtime
from dfdatetime import time_elements


class SerializerTest(unittest.TestCase):
    """Tests for the date and time values serializer."""

    def testConvertDictToDateTimeValues(self):
        """Test ConvertDictToDateTimeValues function."""
        json_dict = {
            "__class_name__": "PosixTime",
            "__type__": "DateTimeValues",
            "timestamp": 1281643591,
        }

        date_time_object = serializer.Serializer.ConvertDictToDateTimeValues(json_dict)
        self.assertIsNotNone(date_time_object)

    def testConvertDateTimeValuesToDict(self):
        """Test ConvertDateTimeValuesToDict function."""
        posix_time_object = posix_time.PosixTime(timestamp=1281643591)
        json_dict = serializer.Serializer.ConvertDateTimeValuesToDict(posix_time_object)
        self.assertIsNotNone(json_dict)

        with self.assertRaises(TypeError):
            serializer.Serializer.ConvertDateTimeValuesToDict("not a datetime")

    def testConvertDateTimeValuesToJSON(self):
        """Test ConvertDateTimeValuesToJSON function."""
        posix_time_object = posix_time.PosixTime(timestamp=1281643591)

        expected_json_dict = {
            "__class_name__": "PosixTime",
            "__type__": "DateTimeValues",
            "timestamp": 1281643591,
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(posix_time_object)
        self.assertEqual(json_dict, expected_json_dict)

        posix_time_object.is_local_time = True
        posix_time_object.time_zone_hint = "Europe/Amsterdam"

        expected_json_dict = {
            "__class_name__": "PosixTime",
            "__type__": "DateTimeValues",
            "is_local_time": True,
            "time_zone_hint": "Europe/Amsterdam",
            "timestamp": 1281643591,
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(posix_time_object)
        self.assertEqual(json_dict, expected_json_dict)

        posix_time_object = posix_time.PosixTime(
            timestamp=1281643591, time_zone_offset=60
        )

        expected_json_dict = {
            "__class_name__": "PosixTime",
            "__type__": "DateTimeValues",
            "timestamp": 1281643591,
            "time_zone_offset": 60,
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(posix_time_object)
        self.assertEqual(json_dict, expected_json_dict)

        never_time_object = semantic_time.Never()

        expected_json_dict = {
            "__class_name__": "Never",
            "__type__": "DateTimeValues",
            "string": "Never",
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(never_time_object)
        self.assertEqual(json_dict, expected_json_dict)

        dotnet_datetime_object = dotnet_datetime.DotNetDateTime(
            timestamp=637433719321230000
        )

        expected_json_dict = {
            "__class_name__": "DotNetDateTime",
            "__type__": "DateTimeValues",
            "timestamp": 637433719321230000,
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            dotnet_datetime_object
        )
        self.assertEqual(json_dict, expected_json_dict)

        fat_date_time_object = fat_date_time.FATDateTime(fat_date_time=0xA8D03D0C)

        expected_json_dict = {
            "__class_name__": "FATDateTime",
            "__type__": "DateTimeValues",
            "fat_date_time": 2832219404,
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            fat_date_time_object
        )
        self.assertEqual(json_dict, expected_json_dict)

        golang_timestamp = bytes.fromhex("01000000000000000200000003ffff")
        golang_time_object = golang_time.GolangTime(golang_timestamp=golang_timestamp)

        expected_json_dict = {
            "__class_name__": "GolangTime",
            "__type__": "DateTimeValues",
            "golang_timestamp": (
                b"\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\xff\xff"
            ),
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            golang_time_object
        )
        self.assertEqual(json_dict, expected_json_dict)

        rfc2579_date_time_object = rfc2579_date_time.RFC2579DateTime(
            rfc2579_date_time_tuple=(2010, 8, 12, 20, 6, 31, 6, "+", 2, 0)
        )

        expected_json_dict = {
            "__class_name__": "RFC2579DateTime",
            "__type__": "DateTimeValues",
            "rfc2579_date_time_tuple": (2010, 8, 12, 20, 6, 31, 6, "+", 2, 0),
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            rfc2579_date_time_object
        )
        self.assertEqual(json_dict, expected_json_dict)

        negative_timezone_rfc2579_object = rfc2579_date_time.RFC2579DateTime(
            rfc2579_date_time_tuple=(2010, 8, 12, 20, 6, 31, 6, "-", 2, 0)
        )

        expected_json_dict = {
            "__class_name__": "RFC2579DateTime",
            "__type__": "DateTimeValues",
            "rfc2579_date_time_tuple": (2010, 8, 12, 20, 6, 31, 6, "-", 2, 0),
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            negative_timezone_rfc2579_object
        )
        self.assertEqual(json_dict, expected_json_dict)

        systemtime_object = systemtime.Systemtime(
            system_time_tuple=(2010, 8, 4, 12, 20, 6, 31, 142)
        )

        expected_json_dict = {
            "__class_name__": "Systemtime",
            "__type__": "DateTimeValues",
            "system_time_tuple": (2010, 8, 4, 12, 20, 6, 31, 142),
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(systemtime_object)
        self.assertEqual(json_dict, expected_json_dict)

        time_elements_object = time_elements.TimeElements(
            is_delta=True, time_elements_tuple=(2010, 8, 12, 20, 6, 31)
        )

        expected_json_dict = {
            "__class_name__": "TimeElements",
            "__type__": "DateTimeValues",
            "is_delta": True,
            "time_elements_tuple": (2010, 8, 12, 20, 6, 31),
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            time_elements_object
        )
        self.assertEqual(json_dict, expected_json_dict)

        time_elements_object = time_elements.TimeElementsInMilliseconds(
            time_elements_tuple=(2010, 8, 12, 20, 6, 31, 546)
        )

        expected_json_dict = {
            "__class_name__": "TimeElementsInMilliseconds",
            "__type__": "DateTimeValues",
            "time_elements_tuple": (2010, 8, 12, 20, 6, 31, 546),
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            time_elements_object
        )
        self.assertEqual(json_dict, expected_json_dict)

        time_elements_object = time_elements.TimeElementsInMicroseconds(
            time_elements_tuple=(2010, 8, 12, 20, 6, 31, 429876)
        )

        expected_json_dict = {
            "__class_name__": "TimeElementsInMicroseconds",
            "__type__": "DateTimeValues",
            "time_elements_tuple": (2010, 8, 12, 20, 6, 31, 429876),
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            time_elements_object
        )
        self.assertEqual(json_dict, expected_json_dict)

        time_elements_object = time_elements.TimeElementsInNanoseconds(
            time_elements_tuple=(2010, 8, 12, 20, 6, 31, 429876543)
        )

        expected_json_dict = {
            "__class_name__": "TimeElementsInNanoseconds",
            "__type__": "DateTimeValues",
            "time_elements_tuple": (2010, 8, 12, 20, 6, 31, 429876543),
        }

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            time_elements_object
        )
        self.assertEqual(json_dict, expected_json_dict)

    def testConvertJSONToDateTimeValues(self):
        """Test ConvertJSONToDateTimeValues function."""
        json_dict = {
            "__class_name__": "PosixTime",
            "__type__": "DateTimeValues",
            "timestamp": 1281643591,
        }

        expected_date_time_object = posix_time.PosixTime(timestamp=1281643591)

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "PosixTime",
            "__type__": "DateTimeValues",
            "is_local_time": True,
            "time_zone_hint": "Europe/Amsterdam",
            "timestamp": 1281643591,
        }

        expected_date_time_object.is_local_time = True
        expected_date_time_object.time_zone_hint = "Europe/Amsterdam"

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "PosixTime",
            "__type__": "DateTimeValues",
            "timestamp": 1281643591,
            "time_zone_offset": 60,
        }

        expected_date_time_object = posix_time.PosixTime(
            timestamp=1281643591, time_zone_offset=60
        )

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "Never",
            "__type__": "DateTimeValues",
            "string": "Never",
        }

        expected_date_time_object = semantic_time.Never()

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "DotNetDateTime",
            "__type__": "DateTimeValues",
            "timestamp": 637433719321230000,
        }

        expected_date_time_object = dotnet_datetime.DotNetDateTime(
            timestamp=637433719321230000
        )

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "FATDateTime",
            "__type__": "DateTimeValues",
            "fat_date_time": 2832219404,
        }

        expected_date_time_object = fat_date_time.FATDateTime(fat_date_time=0xA8D03D0C)

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "GolangTime",
            "__type__": "DateTimeValues",
            "golang_timestamp": (
                b"\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\xff\xff"
            ),
            "time_zone_offset": 60,
        }

        golang_timestamp = bytes.fromhex("01000000000000000200000003ffff")
        expected_date_time_object = golang_time.GolangTime(
            golang_timestamp=golang_timestamp
        )

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "RFC2579DateTime",
            "__type__": "DateTimeValues",
            "rfc2579_date_time_tuple": (2010, 8, 12, 20, 6, 31, 6, "+", 2, 0),
        }

        expected_date_time_object = rfc2579_date_time.RFC2579DateTime(
            rfc2579_date_time_tuple=(2010, 8, 12, 20, 6, 31, 6, "+", 2, 0)
        )

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "Systemtime",
            "__type__": "DateTimeValues",
            "system_time_tuple": (2010, 8, 4, 12, 20, 6, 31, 142),
        }

        expected_date_time_object = systemtime.Systemtime(
            system_time_tuple=(2010, 8, 4, 12, 20, 6, 31, 142)
        )

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "TimeElements",
            "__type__": "DateTimeValues",
            "is_delta": True,
            "time_elements_tuple": (2010, 8, 12, 20, 6, 31),
        }

        expected_date_time_object = time_elements.TimeElements(
            is_delta=True, time_elements_tuple=(2010, 8, 12, 20, 6, 31)
        )

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)
        self.assertTrue(date_time_object.is_delta)

        json_dict = {
            "__class_name__": "TimeElementsInMilliseconds",
            "__type__": "DateTimeValues",
            "time_elements_tuple": (2010, 8, 12, 20, 6, 31, 546),
        }

        expected_date_time_object = time_elements.TimeElementsInMilliseconds(
            time_elements_tuple=(2010, 8, 12, 20, 6, 31, 546)
        )

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "TimeElementsInMicroseconds",
            "__type__": "DateTimeValues",
            "time_elements_tuple": (2010, 8, 12, 20, 6, 31, 429876),
        }

        expected_date_time_object = time_elements.TimeElementsInMicroseconds(
            time_elements_tuple=(2010, 8, 12, 20, 6, 31, 429876)
        )

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        json_dict = {
            "__class_name__": "TimeElementsInNanoseconds",
            "__type__": "DateTimeValues",
            "time_elements_tuple": (2010, 8, 12, 20, 6, 31, 429876543),
        }

        expected_date_time_object = time_elements.TimeElementsInNanoseconds(
            time_elements_tuple=(2010, 8, 12, 20, 6, 31, 429876543)
        )

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(date_time_object, expected_date_time_object)

        # Test if is_delta is removed.
        json_dict = {
            "__class_name__": "PosixTime",
            "__type__": "DateTimeValues",
            "timestamp": 1281643591,
            "is_delta": True,
        }

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertFalse(date_time_object.is_delta)

        with self.assertRaises(KeyError):
            json_dict = {"__class_name__": "UnknownType", "__type__": "DateTimeValues"}
            serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)

    def testCheckRepresentationPairRoundTrip(self):
        """Test CheckRepresentationPairRoundTrip function."""
        first_date_time = posix_time.PosixTimeInNanoseconds(
            timestamp=1281643591546875500
        )
        second_date_time = posix_time.PosixTimeInNanoseconds(
            timestamp=1281643591546875501
        )

        receipt = serializer.Serializer.CheckRepresentationPairRoundTrip(
            first_date_time,
            second_date_time,
            date_text_target_class_name="PosixTimeInMicroseconds",
        )

        self.assertIs(
            receipt.numeric_receipts[0].source_type,
            posix_time.PosixTimeInNanoseconds,
        )
        self.assertEqual(
            receipt.numeric_receipts[0].source_class_name,
            "PosixTimeInNanoseconds",
        )
        self.assertEqual(
            receipt.numeric_receipts[0].status,
            serializer.RoundTripStatus.IDENTICAL,
        )
        self.assertEqual(
            receipt.numeric_receipts[0].payload["__class_name__"],
            "PosixTimeInNanoseconds",
        )
        numeric_payload = json.loads(
            receipt.numeric_receipts[0].serialized_payload
        )
        restored_numeric_values = (
            serializer.Serializer.ConvertNumericPayloadToDateTimeValues(
                numeric_payload
            )
        )
        self.assertEqual(
            numeric_payload["timestamp"], first_date_time.timestamp
        )
        self.assertIsInstance(numeric_payload["timestamp"], int)
        self.assertEqual(
            restored_numeric_values,
            receipt.numeric_receipts[0].restored_date_time_values,
        )
        self.assertEqual(
            receipt.numeric_receipts[1].status,
            serializer.RoundTripStatus.IDENTICAL,
        )
        self.assertFalse(receipt.numeric_payloads_are_identical)
        self.assertFalse(receipt.restored_numeric_values_are_equal)
        self.assertEqual(
            receipt.numeric_receipts[0].restored_date_time_values,
            first_date_time,
        )
        self.assertEqual(
            receipt.numeric_receipts[1].restored_date_time_values,
            second_date_time,
        )

        self.assertEqual(
            receipt.text_receipts[0].status,
            serializer.RoundTripStatus.UNRECOVERABLE,
        )
        self.assertEqual(
            receipt.text_receipts[1].status,
            serializer.RoundTripStatus.UNRECOVERABLE,
        )
        self.assertTrue(receipt.text_payloads_are_identical)
        self.assertTrue(receipt.restored_text_values_are_equal)
        self.assertEqual(
            receipt.text_receipts[0].payload["date_time_string"],
            "2010-08-12 20:06:31.546875",
        )
        self.assertEqual(
            receipt.text_receipts[1].payload["date_time_string"],
            "2010-08-12 20:06:31.546875",
        )
        self.assertEqual(
            receipt.text_receipts[0].source_class_name,
            "PosixTimeInNanoseconds",
        )
        self.assertEqual(
            receipt.text_receipts[0].payload["__class_name__"],
            "PosixTimeInMicroseconds",
        )
        self.assertEqual(
            receipt.text_receipts[0].restored_date_time_values,
            receipt.text_receipts[1].restored_date_time_values,
        )
        self.assertNotEqual(
            receipt.text_receipts[0].restored_date_time_values.timestamp,
            first_date_time.timestamp,
        )

    def testCheckDateTextRoundTripEqual(self):
        """Test CheckDateTextRoundTrip function with an equivalent value."""
        date_time = posix_time.PosixTimeInMicroseconds(
            timestamp=1281643591546875
        )

        receipt = serializer.Serializer.CheckDateTextRoundTrip(date_time)

        self.assertEqual(receipt.status, serializer.RoundTripStatus.IDENTICAL)
        self.assertEqual(
            receipt.payload,
            {
                "__class_name__": "PosixTimeInMicroseconds",
                "__type__": "DateTimeValues",
                "date_time_string": "2010-08-12 20:06:31.546875",
            },
        )
        self.assertEqual(receipt.restored_date_time_values, date_time)

    def testCheckNumericRoundTripEqual(self):
        """Test CheckNumericRoundTrip function with an equivalent value."""
        date_time = posix_time.PosixTime(timestamp=1281643591)

        receipt = serializer.Serializer.CheckNumericRoundTrip(
            date_time, target_class_name="PosixTimeInNanoseconds"
        )

        self.assertEqual(receipt.status, serializer.RoundTripStatus.EQUAL)
        self.assertEqual(receipt.restored_date_time_values, date_time)
        self.assertEqual(
            receipt.payload["__class_name__"], "PosixTimeInNanoseconds"
        )
        self.assertNotEqual(
            type(receipt.restored_date_time_values), type(date_time)
        )

    def testCheckRepresentationPairRoundTripNumericTarget(self):
        """Test pair round-trip with a lower-precision numeric receiver."""
        first_date_time = posix_time.PosixTimeInNanoseconds(
            timestamp=1281643591546875500
        )
        second_date_time = posix_time.PosixTimeInNanoseconds(
            timestamp=1281643591546875501
        )

        receipt = serializer.Serializer.CheckRepresentationPairRoundTrip(
            first_date_time,
            second_date_time,
            numeric_target_class_name="PosixTimeInMicroseconds",
        )

        self.assertTrue(receipt.numeric_payloads_are_identical)
        self.assertTrue(receipt.restored_numeric_values_are_equal)
        self.assertEqual(
            receipt.numeric_receipts[0].status,
            serializer.RoundTripStatus.UNRECOVERABLE,
        )
        self.assertEqual(
            receipt.numeric_receipts[0].payload["timestamp"],
            1281643591546875,
        )

    def testCheckDateTextRoundTripUnrecoverable(self):
        """Test CheckDateTextRoundTrip function with a rounded value."""
        date_time = posix_time.PosixTimeInNanoseconds(
            timestamp=1281643591546875500
        )

        receipt = serializer.Serializer.CheckDateTextRoundTrip(
            date_time, target_class_name="PosixTimeInMicroseconds"
        )

        self.assertEqual(
            receipt.status, serializer.RoundTripStatus.UNRECOVERABLE
        )
        self.assertEqual(
            receipt.payload["date_time_string"], "2010-08-12 20:06:31.546875"
        )
        self.assertNotEqual(
            receipt.restored_date_time_values.timestamp,
            date_time.timestamp,
        )
        self.assertEqual(
            receipt.restored_date_time_values.timestamp,
            1281643591546875,
        )


if __name__ == "__main__":
    unittest.main()
