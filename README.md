![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

## :triangular_flag_on_post: Sponsors

If you like this project, consider sponsoring it on GitHub! [Sponsors](https://github.com/sponsors/skelsec/)

# minidump
Python library to parse and read Microsoft minidump file format. Can create minidumps on Windows machines using the windows API (implemented with ctypes).

# Requirements
Python >= 3.6

# Basic Usage
This module is primarily intended to be used as a library, however for the sake of demonstarting its capabilities there is a command line tool implemented called `minidump`. This tool has the following modes of operation.

#### Console
One-shot parsing and information retrieval.  
  
```minidump.py --all <mindidump file>  ```  
See help for possible options.
#### Shell
There is and interactive command shell to get all info (modules, threads, excetpions etc) and browse the virtual memory of the process dumped (read/read int/read uint/move/peek/tell)  
  
```minidump.py -i <mindidump file>  ```  
Once in the shell, all commands are documented. Use the `?` command to see all options.

# Advanced usage
After parsing the minidump file, you can use the MinidumpFileReader and MinidumpBufferedReader objects to perform various searches/reads in the dumped process' address space.  
Those objects will be able to read and search the VA of the dumped process and have a notion on integer sizes based on the CPU arch.

# Creating minidump file
The ```createminidump.py``` script in the utils folder uses the Windows API to create minidump files. This script can also dump processes running on a different user context by enabling ```SeDebugPrivilege```.  
Of course it only works if you are running it as administrator or a use that has ```SeDebugPrivilege```.

# Installing
```python3 setup.py install```


# Restricted evidence handoff

`minidump.evidence` builds a handoff-ready view that contains only the memory
ranges approved by a work order.  A range is either readable (`raw`) or
page-summary-only (`page_summary`).  Page-summary ranges export page addresses,
sizes, mapping provenance and SHA-256 digests, never their bytes.

```python
from minidump.evidence import ApprovalTicket, EvidencePolicy, EvidenceRange
from minidump.minidumpfile import MinidumpFile

policy = EvidencePolicy(
    ranges=[
        EvidenceRange(0x1000, 0x1100, "raw"),
        EvidenceRange(0x1100, 0x1200, "page_summary"),
        EvidenceRange(0x1200, 0x1300, "page_summary"),
    ],
    ticket=ApprovalTicket("IR-2026-001", issuer="incident-response"),
    page_size=0x1000,
)

dump = MinidumpFile.parse("crash.dmp")
view = dump.get_evidence_view(policy=policy)

raw = view.read(0x1000, 0x20)          # bytes (EvidenceReadResult is bytes)
summary = view.read(0x1100, 0x20)      # summary.data is None
receipt = summary.receipt              # explanations and mapping provenance

# The same address policy applies to the reader and to thread stack access.
reader = view.get_reader()
buffered = view.get_buffered_reader()
stack = view.read_thread_stack(thread_id, offset=0, size=0x20)
```

Every receipt range keeps its original virtual start/end, the minidump stream
(`MemoryListStream` or `Memory64ListStream`), stream RVA, descriptor index and
file RVA, plus the approval ticket.  Truncated policy ranges and ranges
suppressed by a short/missing memory descriptor have separate explanations;
page-summary suppression is explained separately as well.

The view snapshots permitted bytes when it is built; later reads do not consult
the original dump.  A detached handoff bundle is produced with
`view.to_bytes()` and opened with `EvidenceBundle.from_bytes(...)`.  Acceptance
and re-handoff append to the custody chain:

```python
from minidump.evidence import EvidenceBundle

bundle = EvidenceBundle.from_bytes(view.to_bytes())
accepted = bundle.accept("external-contractor")
rehandoff = accepted.rehandoff("forensics-lab", from_actor="external-contractor")

# After acceptance the custodian verifies the original dump byte-for-byte.
verification = rehandoff.verify_original("crash.dmp")
assert verification.ok
```

Run the synthetic-data checks with:

```bash
python -m unittest tests.test_evidence -v
```
