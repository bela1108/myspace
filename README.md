python-evtx
===========

Introduction
------------

python-evtx is a pure Python parser for recent Windows Event Log files (those with the file extension ".evtx").  The module provides programmatic access to the File and Chunk headers, record templates, and event entries.  For example, you can use python-evtx to review the event logs of Windows 7 systems from a Mac or Linux workstation. The structure definitions and parsing strategies were heavily inspired by the work of Andreas Schuster and his Perl implementation "Parse-Evtx".

Background
----------
With the release of Windows Vista, Microsoft introduced an updated event log file format.  The format used in Windows XP was a circular buffer of record structures that each contained a list of strings.  A viewer resolved templates hosted in system library files and inserted the strings into appropriate positions.  The newer event log format is proprietary binary XML.  Unpacking chunks from an event log file from Windows 7 results in a complete XML document with a variable schema.  The changes helped Microsoft tune the file format to real-world uses of event logs, such as long running logs with hundreds of megabytes of data, and system independent template resolution.

Related Work
------------
Andreas Schuster released the first public description of the .evtx file format in 2007.  He is the author of the thorough document "Introducing the Microsoft Vista event log file format" that describes the motivation and details of the format.  Mr. Schuster also maintains the Perl implementation of a parser called "Parse-Evtx".  I referred to the source code of this library extensively during the development of python-evtx.

Joachim Metz also released a cross-platform, LGPL licensed C++ based parser in 2011.  His document "Windows XML Event Log (EVTX): Analysis of EVTX" provides a detailed description of the structures and context of newer event log files.

Dependencies
------------
python-evtx is a pure Python 3 module, so it works equally well across platforms like Windows, macOS, and Linux. 

python-evtx operates on event log files from Windows operating systems newer than Windows Vista.  These files typically have the file extension .evtx.  Version 5.09 of the `file` utility identifies such a file as "MS Vista Windows Event Log".  To manual confirm the file type, look for the ASCII string "ElfFile" in the first seven bytes:

    willi/evtx  » xxd -l 32 Security.evtx 
    0000000: 456c 6646 696c 6500 0000 0000 0000 0000  ElfFile.........
    0000010: d300 0000 0000 0000 375e 0000 0000 0000  ........7^......


Examples
--------
Provided with the parsing module `Evtx` are four scripts that mimic the tools distributed with Parse-Evtx.  `evtx_info.py` prints metadata about the event log and verifies the checksums of each chunk.  `evtx_templates.py` builds and prints the templates used throughout the event log. `evtx_dump.py` parses the event log and transforms the binary XML into a human readable ASCII XML format. Finally, `evtx_dump_json.py` parses event logs, similar to `evtx_dump.py` and transforms the binary XML into JSON with the added capability to output the JSON array to a file. 

Note the length of the `evtx_dump.py` script: its only 20 lines.  Now, review the contents and notice the complete implementation of the logic:

    print(e_views.XML_HEADER)
    print('<Events>')
    for record in log.records:
        print(record.xml())
    print('</Events>')  

Working with python-evtx is really easy!


Offline timeline diagnostics
----------------------------
`Evtx.Timeline` adds an offline diagnostic for timelines that contain both a
host-clock rollback and damage in the original EVTX file.  It keeps three
ordering sources separate rather than normalizing them into one guessed time:

- `original-record`: physical record order, record numbers, chunk boundaries,
  bad-record/bad-chunk gaps, and the timestamps stored in the records.
- `event-time`: the parseable `System/TimeCreated@SystemTime` values.  A
  backward step is reported as a clock rollback and is *not* rewritten.
- `collection`: a receipt/acknowledgement manifest supplied by the collector:
  receipt sequence, receipt time, block/record identifiers, and explicit loss
  markers.

The command-line diagnostic is available as `evtx_timeline` (and
`evtx_timeline_diagnostic`):

    evtx_timeline HOST.evtx \
        --collection collection-receipts.json \
        --numbering "4624=EventRecordID,scope=file" \
        --numbering "4688=EventData/SequenceNumber" \
        --output timeline.json

The result contains `records`, `discontinuities`, `time_inversions`,
`clock_rollbacks`, `timeline`, and `constraints`.  Every timeline entry has a
`basis` (`original-record` or `collection`), a `bases` list, and an `evidence`
list.  Missing chunks, unparseable records, and explicit collection losses are
retained as discontinuity entries; the scanner searches for the next plausible
8-byte-aligned record rather than silently discarding the rest of a chunk.

A collection manifest may be JSON, JSONL, or CSV.  For example:

    {
      "block_size": 65536,
      "receipts": [
        {"receipt_sequence": 1, "record_number": 12049, "received_at": "2026-11-21T10:00:00Z"},
        {"receipt_sequence": 2, "record_number": 12050, "received_at": "2026-11-21T10:00:01Z"},
        {"receipt_sequence": 4, "record_number": 12052, "received_at": "2026-11-21T10:00:03Z"},
        {"receipt_sequence": 5, "status": "missing", "block_index": 7}
      ],
      "missing_blocks": [8, 9]
    }

Per-EventID numbering is never inferred.  The caller must provide explicit
rules.  `scope: "event-id"` means each EventID has an independent counter;
`scope: "file"` means the field is one file-wide counter shared by all records.
The field can be a record pseudo-field (`record_number`, `EventRecordID`) or a
simple XML path such as `EventData/SequenceNumber` or
`EventData/Data[@Name='SequenceNumber']`.

    {
      "rules": [
        {"event_id": 4624, "field": "EventRecordID", "scope": "file"},
        {"event_id": 4688, "field": "EventData/SequenceNumber", "scope": "event-id"}
      ]
    }

From Python:

    from Evtx.Timeline import diagnose_timeline

    result = diagnose_timeline(
        "HOST.evtx",
        collection="collection-receipts.json",
        numbering_rules=[
            {"event_id": 4624, "field": "EventRecordID", "scope": "file"},
        ],
    )
    print(result.summary)
    for entry in result.timeline:
        print(entry.position, entry.kind, entry.bases, entry.detail)


Installation
------------
Updates to python-evtx are pushed to PyPi, so you can install the module using `pip`.  For example:

    pip install python-evtx

The source code for python-evtx is hosted at Github, and you may download, fork, and review it from this repository (http://www.github.com/williballenthin/python-evtx).  Please report issues or feature requests through Github's bug tracker associated with the project.

Development
-----------
For formatting, use isort:
    
    isort --length-sort --profile black --line-length=120 Evtx/ scripts/ tests/

and black:

    black --line-length=120 Evtx/ scripts/ tests/

For linting, use ruff:

    ruff check Evtx/ scripts/ tests/

Or use [just](https://github.com/casey/just) to run the linters:

    just lint

License
-------
python-evtx is licensed under the Apache License, Version 2.0.  This means it is freely available for use and modification in a personal and professional capacity.  

