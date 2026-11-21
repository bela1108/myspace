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

## Context comparison (postmortem reports)
The exception stream context is captured at exception time; a thread-list
context is only a normal thread snapshot. They can be compared without
treating the two as equivalent evidence:

```python
from minidump.minidumpfile import MinidumpFile

dump = MinidumpFile.parse("crash.dmp")
comparison = dump.get_context_comparison()  # or thread_id=0x1234
print(comparison.to_report())
```

Each register row carries its source (`exception` or `thread`), `ContextFlags`
validity, and a status. A register that exists only in the thread context is
reported as normal-thread-state-only. Missing context pages and unknown
architectures keep their raw bytes and RVA provenance; unavailable values are
reported as unknown, never fabricated as zero.

CLI:

```
minidump --context-compare crash.dmp [--thread-id 0x1234]
```
