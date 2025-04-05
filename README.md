# NT-Dolphin
NT-Dolphin (Network Trace Dolphin) is a collection of very simple and highly performant network trace TCP/UDP filtering programs for Windows and Linux.

![NT-Dolphin](/Icons/NT-Dolphin_blue.ico)

It is written from scratch in C and has no dependencies.

| PCAP_Dolphin   | pcap file -> filtered pcap file   |
| -------------- | --------------------------------- |
| PCAPng_Dolphin | pcapng file -> filtered pcap file |

# Compilation
Linux
```
cd NT-Dolphin/PCAP_Dolphin/linux
#or 
cd NT-Dolphin/PCAPng_Dolphin/linux

make all
```
Windows
Open the Visual Studio project and compile with Release settings (debug generates too much overhead).
# Usage
## Config.ini
The first step is to adjust the `config.ini` file in the same directory as the executable (applies to both Windows and Linux).
### Example config.ini
```
; If any of the ports match on the sender or receiver side the filter will pass
[Filter]
UDP = 53
TCP = 80, 443
```
Any port added to this config file will be included in the output file if either the source or destination port matches.
Comments can be added using the `;` symbol. If either TCP or UDP ports are not required the line can be simply commented out.  
## Linux
```
./pcapdolphin input.pcap
or
./pcapngdolphin input.pcapng
```
This will generate a new file in the same folder: `input_filtered.pcap` 
## Windows
Drag&Drop or use the command line:
```
.\PCAP_Dolphin.exe input.pcap
or
.\PCAPng_Dolphin.exe input.pcapng
```
This will generate a new file in the same folder: `input_filtered.pcap` 

# Restrictions
Only the PCAP output file format is currently supported by both PCAP_Dolphin and PCAPng_Dolphin.
## Supported Protocols
- Ethernet
- VLAN
- IPv6/IPv4
- ICMPv6 / ICMP(for IPv4) (IPv4/IPv6 messages inside ICMP/ICMPv6 messages are also scanned to check for TCP/UDP port matches)
- TCP
- UDP
## Unintuitive restrictions
- The current way of file handling/rename scheme only allows files to be processed with a ".pcap"/".pcapng" suffix
- NT-Dolphin Programs only work on little endian (X86/X64) systems and for little-endian PCAPs/PCAPngs (PCAPs/PCAPngs can be big-endian if recorded big-endian machines like ARM based machines)
- IPv6 extensions are currently not supported. Messages containing any extensions are filtered out by default.
- There is no option to save the output file to a different location than the input file's location.
- Additionally, files with the same output filename will be overwritten without confirmation.
- PCAPng Dolphin: Currently a messy implementation of the time_scale could messup the timestamps if interfaces with different time_scales are used at the same time (rare)
- PCAPng Dolphin: The Packet Block Types "Packet Block" and "Simple Packet Block" are not supported but are also unlikely to be relevant.

# Performance
I started this project under the belief that network trace filtering was CPU-intensive, as tools like Wireshark and Scapy suggest. However, after finishing my first draft, I was surprised to find that performance was mainly limited by storage speed.

A cached SSD will use the time while the CPU is calculating, to load the data into its cache, practically nullifying the amount of time needed for the calculations. 

Therefore on any modern cached SSD the speed of filtering is very close to: 
```
max sequential read speed * input file size + max sequential write speed * output file size 
```

# Goals of this project
- High performance
- Easily portable and compilable on any Windows/Linux system
- Simple code structure

# Planned Features:
- Support IPv6 extensions
- Support Big-Endian
- Support filtering by specific source/destination ports instead of just any matching port
- Support filtering for IP addresses (also with source + destination)
- Support block-size options in the config file
- The output file naming scheme needs a rework
- Rework String handling (unicode support with output files)
- Support silent switch/parameter or a rather a verbose switch/parameter
- Improving Performance by only loading in required bytes from file
- Rework File Handlers, the way it is done now is simply not optimal
- Support parameter options overruling config file
- Merge projects into single Project 
- Support `.pcapng` output.
- Add more input (and output?) file formats like Vector (C) BLF
- Rework usage of INT -> use fixed size datatypes (e.g. UINT_32)

# Inner working of NT-Dolphin:
All NT-Dolphin Programs work like this:
Read a PCAP file into RAM (in chunks/blocks), search through the content, and write it to a new file if the ports match.
Look for Ethernet header -> VLAN/IPv6 -> TCP/UDP -> decide if port is in filter -> return true/false
After that the Messages with the right Flags will be written into a new PCAP File

## Memory usage/Block idea/Ring-buffer:
Blocks load in chunks of the file. You should have enough space/RAM for two blocks. Each block must have enough space for at least one packet (~2KB). To avoid potential issues, a minimum of 4KB per block is always used.
NT-Dolphin uses Ring-buffers to go through the file, where 2 blocks of the file are always loaded in:
Load in first Block of the file and use it as normal.
Before accessing a packet, check its size. If it exceeds the current block's boundaries, load the next block into the unused buffer.
Access to buffer should always be done with the BLOCK_POSITION(x) preprocess macro, as it returns the current position of the byte in the ring-buffer after mapping the file byte location to the ring buffer location.

## Non-Alignment
Another consideration to be taken into account is the non-alignment of multiple bytes. For example accessing an int always needs 4 bytes (on x86/x64 gcc/MSVC) which are all located right beside each other.
As the packages in the pcap can totally differ in their size, the following case can become true:
The first byte of an `int` may be located at the last position of the second block, while the remaining three bytes are in the first block.
Since buffer access is limited to `int` values (no `long long`s or strings), I copy the first three bytes of the first block to the space right after the second block when loading data. By this I avoid using `int`s out of bound. But this limits the usage of read/write-operations inside of the ringbuffer to operations of max 4 bytes per atomic operation.

## Performance considerations, or why the usage of clock() is different under Windows/Linux :
While the `clock()` function appears efficient on Windows, it performs poorly on Linux systems (tested on multiple machines running dual-boot configurations with Windows and Linux distributions such as Ubuntu, Manjaro, and Debian).
This inefficiency caused the Linux program to run up to 10 times slower, which is why `clock()` function calls in the main calculation loop are disabled by macros when compiled for Linux.
As a result, on Linux systems, there are no time measurements for loading, processing, or saving output files.


# Licensing & Copy Right
## Copyright

© 2020-2025 Martin Albert. All rights reserved.

## License

This project is licensed under the **MIT License**. See the LICENSE file for details.

### Third-Party Dependencies

This project uses the **inih** library, which is licensed under the **BSD-3-Clause License**:
```
inih -- simple .INI file parser  
SPDX-License-Identifier: BSD-3-Clause  
Copyright (C) 2009-2020, Ben Hoyt  
```
For more information, see the [inih GitHub repository](https://github.com/benhoyt/inih) and its [LICENSE.txt](https://github.com/benhoyt/inih/blob/master/LICENSE.txt).