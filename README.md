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

# Excerpt manifest backend (minidump.excerpt)
When a supplier only needs a small portion of a dump (e.g. around the crash) but the full dump contains user data, the `minidump.excerpt` subpackage lets the dump owner publish a **manifest** instead of the bytes:
- The manifest binds caller-authorized memory to the original dump's SHA-256 digest and to virtual address ranges.
- The public manifest view exposes coverage relations and hashes only - never memory content.
- Multiple descriptions of the same region are indexed in a directory and stay traceable via `derived_from` lineage (`ExcerptManifest.trace`).
- Unknown pages inside an authorized range are recorded as explicit gaps and are never zero-filled or signed.
- A local verification endpoint (`minidump.excerpt.server`) serves the public manifest (`GET /manifest`) and verifies excerpts (`POST /verify`), reporting the exact virtual address range of any segment that exceeds the authorization.

Run the self-contained demo (synthetic dump + two excerpts, one valid and one splicing in an adjacent unauthorized page):
```python3 -m minidump.excerpt```

# Installing
```python3 setup.py install```
