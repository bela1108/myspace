"""Build standard Windows Event XML trees from plain event dictionaries."""

from __future__ import annotations

from .evtx_writer import XmlElement

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _text_element(name: str, text: str) -> XmlElement:
    return XmlElement(name, {}, [], text)


def build_event_root(event: dict) -> XmlElement:
    system_children = [
        _text_element("Provider", "") if False else _text_element("EventID", str(event["event_id"])),
        _text_element("Computer", str(event.get("computer", ""))),
    ]
    system = XmlElement("System", {}, system_children)
    data_children = [_text_element(str(key), str(value)) for key, value in event.get("data", {}).items()]
    event_data = XmlElement("EventData", {}, data_children)
    root = XmlElement("Event", {"xmlns": EVENT_NS}, [system, event_data])
    return root
