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

For memory which may include uncaptured gaps, use an evidence-aware range query:

```python
from minidump.minidumpfile import MinidumpFile

reader = MinidumpFile.parse("dump.dmp").get_reader()
for interval in reader.read_range_with_evidence(0x1000, 0x1006):
	print(hex(interval.start), hex(interval.end), interval.kind)
	print(interval.data_stream, interval.memory_info)
```

The range is half-open. `sampled_zero` bytes are present in a memory data stream, `display_zero` bytes are zero-filled because only the memory-info table covers them, and `uncovered` ranges have neither source. Adjacent ranges with different evidence are never merged, even when both contain the same zero bytes.

# Creating minidump file
The ```createminidump.py``` script in the utils folder uses the Windows API to create minidump files. This script can also dump processes running on a different user context by enabling ```SeDebugPrivilege```.  
Of course it only works if you are running it as administrator or a use that has ```SeDebugPrivilege```.

# Installing
```python3 setup.py install```
