"""The date and time values serializer."""

import copy
import json

from dfdatetime import factory
from dfdatetime import interface


class RoundTripStatus:
    """Status values for a date and time representation round-trip."""

    IDENTICAL = "identical"
    EQUAL = "equal"
    UNRECOVERABLE = "unrecoverable"


class RoundTripReceipt:
    """Receipt for a date and time representation round-trip.

    Attributes:
      representation (str): name of the transport representation.
      source_class_name (str): class name of the source date and time values.
      source_type (type): type of the source date and time values.
      payload (object): value sent using the transport representation.
      serialized_payload (Optional[str]): serialized payload, if available.
      restored_date_time_values (DateTimeValues): date and time values restored
          from the payload or None if they could not be restored.
      status (str): one of the statuses defined by RoundTripStatus.
    """

    def __init__(
        self,
        representation,
        source_date_time_values,
        payload,
        serialized_payload,
        restored_date_time_values,
        status,
    ):
        """Initializes a round-trip receipt.

        Args:
          representation (str): name of the transport representation.
          source_date_time_values (DateTimeValues): source date and time values.
          payload (object): value sent using the transport representation.
          serialized_payload (Optional[str]): serialized payload, if available.
          restored_date_time_values (DateTimeValues): date and time values restored
              from the payload or None if they could not be restored.
          status (str): one of the statuses defined by RoundTripStatus.
        """
        self.representation = representation
        self.source_class_name = type(source_date_time_values).__name__
        self.source_type = type(source_date_time_values)
        self.payload = payload
        self.serialized_payload = serialized_payload
        self.restored_date_time_values = restored_date_time_values
        self.status = status


class RepresentationPairReceipt:
    """Receipt for numeric and date text representation round-trips.

    Attributes:
      first_date_time_values (DateTimeValues): first source date and time
          values.
      second_date_time_values (DateTimeValues): second source date and time
          values.
      numeric_receipts (tuple[RoundTripReceipt, RoundTripReceipt]): numeric
          round-trip receipts for the first and second source values.
      text_receipts (tuple[RoundTripReceipt, RoundTripReceipt]): date text
          round-trip receipts for the first and second source values.
    """

    def __init__(
        self, first_date_time_values, second_date_time_values, receipts
    ):
        """Initializes a representation pair receipt.

        Args:
          first_date_time_values (DateTimeValues): first source date and time
              values.
          second_date_time_values (DateTimeValues): second source date and time
              values.
          receipts (dict[str, tuple[RoundTripReceipt, RoundTripReceipt]]): numeric
              and date text round-trip receipts keyed by representation name.
        """
        self.first_date_time_values = first_date_time_values
        self.second_date_time_values = second_date_time_values
        self.numeric_receipts = receipts["numeric"]
        self.text_receipts = receipts["date_text"]

    @property
    def numeric_payloads_are_identical(self):
        """bool: True if the numeric payloads represent identical values."""
        return (
            self.numeric_receipts[0].payload
            == self.numeric_receipts[1].payload
        )

    @property
    def text_payloads_are_identical(self):
        """bool: True if the date text payloads represent identical values."""
        return self.text_receipts[0].payload == self.text_receipts[1].payload

    @property
    def restored_numeric_values_are_equal(self):
        """bool: True if values restored from numeric payloads are equal."""
        first_values = self.numeric_receipts[0].restored_date_time_values
        second_values = self.numeric_receipts[1].restored_date_time_values
        return first_values == second_values

    @property
    def restored_text_values_are_equal(self):
        """bool: True if values restored from text payloads are equal."""
        first_values = self.text_receipts[0].restored_date_time_values
        second_values = self.text_receipts[1].restored_date_time_values
        return first_values == second_values


class Serializer:
    """Date and time values serializer."""

    @classmethod
    def ConvertDictToDateTimeValues(cls, json_dict):
        """Converts a JSON dict into a date time values object.

        This method is deprecated use ConvertJSONToDateTimeValues instead.

        The dictionary of the JSON serialized objects consists of:
        {
            '__type__': 'DateTimeValues'
            '__class_name__': 'RFC2579DateTime'
            ...
        }

        Here '__type__' indicates the object base type. In this case this should
        be 'DateTimeValues'. The rest of the elements of the dictionary make up the
        date time values object properties.

        Args:
          json_dict (dict[str, object]): JSON serialized objects.

        Returns:
          dfdatetime.DateTimeValues: date and time values.
        """
        return cls.ConvertJSONToDateTimeValues(json_dict)

    @classmethod
    def ConvertDateTimeValuesToDict(cls, date_time_values):
        """Converts a date and time values object into a JSON dictionary.

        This method is deprecated use ConvertDateTimeValuesToJSON instead.

        The resulting dictionary of the JSON serialized objects consists of:
        {
            '__type__': 'DateTimeValues'
            '__class_name__': 'RFC2579DateTime'
            ...
        }

        Here '__type__' indicates the object base type. In this case
        'DateTimeValues'. The rest of the elements of the dictionary make up the
        date and time value object properties.

        Args:
          date_time_values (dfdatetime.DateTimeValues): date and time values.

        Returns:
          dict[str, object]: JSON serialized objects.

        Raises:
          TypeError: if object is not an instance of DateTimeValues.
        """
        if not isinstance(date_time_values, interface.DateTimeValues):
            raise TypeError

        return cls.ConvertDateTimeValuesToJSON(date_time_values)

    @classmethod
    def ConvertDateTimeValuesToJSON(cls, date_time_values):
        """Converts a date and time values object into a JSON dictionary.

        The resulting dictionary of the JSON serialized objects consists of:
        {
            '__type__': 'DateTimeValues'
            '__class_name__': 'RFC2579DateTime'
            ...
        }

        Here '__type__' indicates the object base type. In this case
        'DateTimeValues'. The rest of the elements of the dictionary make up the
        date and time value object properties.

        Args:
          date_time_values (dfdatetime.DateTimeValues): date and time values.

        Returns:
          dict[str, object]: JSON serialized objects.
        """
        return date_time_values.CopyToSerializableDict()

    @classmethod
    def ConvertJSONToDateTimeValues(cls, json_dict):
        """Converts a JSON dict into a date time values object.

        The dictionary of the JSON serialized objects consists of:
        {
            '__type__': 'DateTimeValues'
            '__class_name__': 'RFC2579DateTime'
            ...
        }

        Here '__type__' indicates the object base type. In this case this should
        be 'DateTimeValues'. The rest of the elements of the dictionary make up the
        date time values object properties.

        Args:
          json_dict (dict[str, object]): JSON serialized objects.

        Returns:
          dfdatetime.DateTimeValues: date and time values.

        Raises:
          KeyError: If date and time values type is not supported by factory.
        """
        class_name = json_dict.get("__class_name__")
        if class_name:
            del json_dict["__class_name__"]

        # Remove the class type from the JSON dict since we cannot pass it.
        del json_dict["__type__"]

        if class_name not in (
            "TimeElements",
            "TimeElementsInMilliseconds",
            "TimeElementsInMicroseconds",
            "TimeElementsInNanoseconds",
        ):
            is_delta = json_dict.get("is_delta")
            if is_delta is not None:
                del json_dict["is_delta"]

        is_local_time = json_dict.get("is_local_time")
        if is_local_time is not None:
            del json_dict["is_local_time"]

        time_zone_hint = json_dict.get("time_zone_hint")
        if time_zone_hint is not None:
            del json_dict["time_zone_hint"]

        if class_name in ("InvalidTime", "Never", "NotSet"):
            string = json_dict.get("string")
            if string is not None:
                del json_dict["string"]

        if class_name in ("GolangTime", "RFC2579DateTime"):
            time_zone_offset = json_dict.get("time_zone_offset")
            if time_zone_offset is not None:
                del json_dict["time_zone_offset"]

        date_time = factory.Factory.NewDateTimeValues(class_name, **json_dict)
        if is_local_time:
            date_time.is_local_time = is_local_time
        if time_zone_hint:
            date_time.time_zone_hint = time_zone_hint

        return date_time

    @classmethod
    def ConvertDateTimeValuesToNumericPayload(cls, date_time_values):
        """Converts date and time values to a JSON-compatible numeric payload.

        Args:
          date_time_values (DateTimeValues): source date and time values.

        Returns:
          dict[str, object]: JSON-compatible dictionary containing numeric source
              fields.

        Raises:
          TypeError: if object is not an instance of DateTimeValues.
        """
        if not isinstance(date_time_values, interface.DateTimeValues):
            raise TypeError

        return copy.deepcopy(
            cls.ConvertDateTimeValuesToJSON(date_time_values)
        )

    @classmethod
    def ConvertDateTimeValuesToDateTextPayload(
        cls, date_time_values, target_class_name=None
    ):
        """Converts date and time values to a date text payload.

        Args:
          date_time_values (DateTimeValues): source date and time values.
          target_class_name (Optional[str]): class name of the date and time type
              accepted by the text receiver or None to use the source type.

        Returns:
          dict[str, object]: payload containing the date and time text and the
              receiver type.

        Raises:
          TypeError: if object is not an instance of DateTimeValues.
        """
        if not isinstance(date_time_values, interface.DateTimeValues):
            raise TypeError

        if target_class_name is None:
            target_class_name = type(date_time_values).__name__

        if target_class_name == type(date_time_values).__name__:
            target_date_time_values = date_time_values
        else:
            target_date_time_values = factory.Factory.NewDateTimeValues(
                target_class_name
            )
            target_date_time_values.CopyFromDateTimeString(
                date_time_values.CopyToDateTimeString()
            )

        return {
            "__class_name__": target_class_name,
            "__type__": "DateTimeValues",
            "date_time_string": (
                target_date_time_values.CopyToDateTimeString()
            ),
        }

    @classmethod
    def ConvertNumericPayloadToDateTimeValues(cls, payload):
        """Converts a JSON-compatible numeric payload to date and time values.

        Args:
          payload (dict[str, object]): JSON-compatible numeric payload.

        Returns:
          DateTimeValues: date and time values.
        """
        return cls.ConvertJSONToDateTimeValues(copy.deepcopy(payload))

    @classmethod
    def ConvertDateTextPayloadToDateTimeValues(cls, payload):
        """Converts a date text payload to date and time values.

        Args:
          payload (dict[str, object]): date text payload.

        Returns:
          DateTimeValues: date and time values.
        """
        class_name = payload["__class_name__"]
        date_time_values = factory.Factory.NewDateTimeValues(class_name)
        date_time_values.CopyFromDateTimeString(payload["date_time_string"])
        return date_time_values

    @classmethod
    def CheckNumericRoundTrip(cls, date_time_values, target_class_name=None):
        """Checks an in-memory numeric representation round-trip.

        Args:
          date_time_values (DateTimeValues): source date and time values.
          target_class_name (Optional[str]): class name of the date and time
              type accepted by the numeric receiver or None to use the source
              type.

        Returns:
          RoundTripReceipt: round-trip receipt.

        Raises:
          TypeError: if object is not an instance of DateTimeValues.
        """
        if not isinstance(date_time_values, interface.DateTimeValues):
            raise TypeError

        if target_class_name is None:
            target_class_name = type(date_time_values).__name__

        if target_class_name == type(date_time_values).__name__:
            payload = cls.ConvertDateTimeValuesToNumericPayload(date_time_values)
        else:
            target_date_time_values = factory.Factory.NewDateTimeValues(
                target_class_name
            )
            target_date_time_values.CopyFromDateTimeString(
                date_time_values.CopyToDateTimeString()
            )
            payload = cls.ConvertDateTimeValuesToNumericPayload(
                target_date_time_values
            )
        source_payload = cls.ConvertDateTimeValuesToNumericPayload(date_time_values)
        serialized_payload = json.dumps(payload)
        restored_date_time_values = cls.ConvertNumericPayloadToDateTimeValues(
            payload
        )
        restored_payload = cls.ConvertDateTimeValuesToNumericPayload(
            restored_date_time_values
        )

        if source_payload == restored_payload:
            status = RoundTripStatus.IDENTICAL
        elif restored_date_time_values == date_time_values:
            status = RoundTripStatus.EQUAL
        else:
            status = RoundTripStatus.UNRECOVERABLE

        return RoundTripReceipt(
            "numeric",
            date_time_values,
            payload,
            serialized_payload,
            restored_date_time_values,
            status,
        )

    @classmethod
    def CheckDateTextRoundTrip(cls, date_time_values, target_class_name=None):
        """Checks an in-memory date text representation round-trip.

        Args:
          date_time_values (DateTimeValues): source date and time values.
          target_class_name (Optional[str]): class name of the date and time type
              accepted by the text receiver or None to use the source type.

        Returns:
          RoundTripReceipt: round-trip receipt.

        Raises:
          TypeError: if object is not an instance of DateTimeValues.
        """
        if not isinstance(date_time_values, interface.DateTimeValues):
            raise TypeError

        payload = cls.ConvertDateTimeValuesToDateTextPayload(
            date_time_values, target_class_name=target_class_name
        )
        source_payload = cls.ConvertDateTimeValuesToDateTextPayload(
            date_time_values
        )
        restored_date_time_values = cls.ConvertDateTextPayloadToDateTimeValues(
            payload
        )
        restored_payload = cls.ConvertDateTimeValuesToDateTextPayload(
            restored_date_time_values
        )

        if source_payload == restored_payload:
            status = RoundTripStatus.IDENTICAL
        elif restored_date_time_values == date_time_values:
            status = RoundTripStatus.EQUAL
        else:
            status = RoundTripStatus.UNRECOVERABLE

        return RoundTripReceipt(
            "date_text",
            date_time_values,
            payload,
            None,
            restored_date_time_values,
            status,
        )

    @classmethod
    def CheckRepresentationPairRoundTrip(
        cls,
        first_date_time_values,
        second_date_time_values,
        numeric_target_class_name=None,
        date_text_target_class_name=None,
    ):
        """Checks numeric and date text round-trips for two date time values.

        Args:
          first_date_time_values (DateTimeValues): first source date and time
              values.
          second_date_time_values (DateTimeValues): second source date and time
              values.
          numeric_target_class_name (Optional[str]): class name of the date and
              time type accepted by the numeric receiver or None to use the source
              type.
          date_text_target_class_name (Optional[str]): class name of the date and
              time type accepted by the text receiver or None to use the source
              type.

        Returns:
          RepresentationPairReceipt: pair round-trip receipt.

        Raises:
          TypeError: if either object is not an instance of DateTimeValues.
        """
        if not isinstance(first_date_time_values, interface.DateTimeValues):
            raise TypeError
        if not isinstance(second_date_time_values, interface.DateTimeValues):
            raise TypeError

        receipts = {
            "numeric": (
                cls.CheckNumericRoundTrip(
                    first_date_time_values,
                    target_class_name=numeric_target_class_name,
                ),
                cls.CheckNumericRoundTrip(
                    second_date_time_values,
                    target_class_name=numeric_target_class_name,
                ),
            ),
            "date_text": (
                cls.CheckDateTextRoundTrip(
                    first_date_time_values,
                    target_class_name=date_text_target_class_name,
                ),
                cls.CheckDateTextRoundTrip(
                    second_date_time_values,
                    target_class_name=date_text_target_class_name,
                ),
            ),
        }
        return RepresentationPairReceipt(
            first_date_time_values, second_date_time_values, receipts
        )
