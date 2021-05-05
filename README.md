# FalconEye: Real-time detection software for Windows process injections

FalconEye is a windows endpoint detection software for real-time process
injections.

You can check our presentation at [2021 Blackhat ASIA Arsenal](https://www.blackhat.com/asia-21/arsenal/schedule/#falconeye-windows-process-injection-techniques---catch-them-all-22612) and [slides](https://github.com/rajiv2790/FalconEye/blob/main/2021BHASIA_FalconEye.pdf).

## Project Overview

### Detection Coverage
| Technique     | Status      | Detection  |
| ------------- | ------------- | -----------|
| Atombombing   | &check;         |  |
| Instrumentation callback injection      | &check;        |    |
| PROPGate | &check;       |    |
| CreateRemoteThread with LoadLibrary| &check;       |    |
| CreateRemoteThread with MapViewOfFile | &check;       |    |
| Suspend-Injection-Resume | &check;       |    |
| QueueUserAPC | &check;       |    |
| QueueUserAPC with memset (Stackbombing) | &check;       |    |
| SetWindowLong (Extra window memory injection) | &check;       |    |
| Unmap + Overwrite | &check;       |    |
| Kernel Ctrl Table | &check;       |    |
| USERDATA | &check;       |    |
| Ctrl-inject | &check;       |    |
| ALPC Callback | &check;       |    |
| WNF Callback | &check;       |    |
| SetWindowsHook | &check;       |    |
| Service Control | &check;       |    |
| Shellcode injection | &check;       |    |
| Image Mapping | &check;       |    |
| Thread Reuse | &check;       |    |
| GhostWriting | &check;       |    |
| Process Hollowing | &check;       |    |

###Architecture Overview

![alt text](diagrams/FalconEye_Software_Architecture.png)

## Files
```bash
.
├── src 
│   ├── FalconEye ---------------------------# FalconEye user and kernel space
implementations
│   └── libinfinityhook ---------------------# Kernel hook implementation
├── 2021BHASIA_FalconEye.pdf
├── README.md
```

## Getting Started


### Prerequisite


## Tips

## Software Requirements

## License Terms
FalconEye is licensed to you under [Apache 2.0](COPYING) open source license. 
