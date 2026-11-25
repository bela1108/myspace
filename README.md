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

# Read-only impact analysis (stream trimming)
When minidumps are compressed or trimmed, individual streams can be dropped. The package ships a strictly read-only analyzer that answers, for a caller supplied investigation path, whether a stream is required, substitutable (a sibling stream or a degraded path carries the same evidence) or merely explanatory. It reverse-looks-up directory entries, threads, exception records and stack/context location descriptors, and reports dangling references where a directory entry survived but its backing data no longer resolves inside the file. No process memory bytes are ever read or returned; only RVA/size/virtual-address metadata and status flags are reported.

Library entry point:
```
from minidump.minidumpfile import MinidumpFile
mf = MinidumpFile.parse("sample.dmp")
report = mf.investigate("crash")   # or "threads", or "directory,thread,context,stack"
print(report.verdict)                # full / partial reconstruction possible, or blocked
print(report.to_dict())              # machine readable, memory-content free
```
CLI:
```
minidump --investigate crash sample.dmp            # human readable report
minidump --investigate crash --json sample.dmp     # pure JSON (no banner)
```

The verdict distinguishes a fully reconstructable dump, a partially reconstructable dump (a substitutable stream such as the module or memory list is missing) and a blocked dump (a required stream is absent or its entry dangles).
