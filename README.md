# FalconEye: Real-time detection software for Windows process injections

FalconEye is a windows endpoint detection software for real-time process injections. It is a kernel-mode driver that aims to catch process injections as they are happening (real-time). Since FalconEye runs in kernel mode, it provides a stronger and reliable defense against process injection techniques that try to evade various user-mode hooks.

You can check our presentation at [2021 Blackhat ASIA Arsenal](https://www.blackhat.com/asia-21/arsenal/schedule/#falconeye-windows-process-injection-techniques---catch-them-all-22612) and [slides](https://github.com/rajiv2790/FalconEye/blob/main/2021BHASIA_FalconEye.pdf).

## Project Overview

### Detection Coverage

The table below shows the implementation status and the detection logic for the various
process injection techniques. WPM stands for WriteProcessMemory. To test the
detection, one can refer to the references section. 

| Technique                                     | Status  | Detection  | POC Used  |
| -------------                                 | ------- | -----------| ----------|
| Atombombing                                   | &check; | Hook QueueUserAPC and look for GlobalGetAtom family of functions | Pinjectra |
| Instrumentation callback injection            | &check; | Detect if a new thread is created from floating code | https://github.com/antonioCoco/Mapping-Injection |
| Reflective DLL Injection                      | &check; | Detect if a new thread is created from floating code and if PE header is being written into victim| MInjector |
| PROPagate                                     | &check; | Hook SetProp to get the address of the property being written and corelate with the previous WPM calls to get the address of floating code | Pinjectra |
| Process Hollowing                             | &check; | Detected using PE header written into target process memory | MInjector |
| CreateRemoteThread with LoadLibrary           | &check; | New thread with start address pointing to LoadLibrary. MInjector version also writes DLL path using WPM which is also detected | MInjector, Pinjectra |
| CreateRemoteThread with MapViewOfFile         | &check; | Detect if a new thread is created from floating code | Pinjectra |
| Suspend-Inject-Resume                         | &check; | Detect if a new thread is created from floating code(MInjector). DLL Path being written via WPM (MInjector). Detect if context set on a previously suspended thread (Pinjectra) | MInjector, Pinjectra |
| QueueUserAPC                                  | &check; | DLL path being written via WPM | MInjector |
| QueueUserAPC with memset (Stackbombing)       | &check; | Hook QueueUserAPC and look for memset | Pinjectra |
| SetWindowLong (Extra window memory injection) | &check; | Hook SetWindowLong to get the address of the function pointer being written and corelate with the previous WPM calls to get the address of floating code | Pinjectra |
| Unmap + Overwrite                             | &check; | Alert if attacker process is unmapping ntdll from the victim | Pinjectra |
| Kernel Ctrl Table                             | &check; | Detect if WPM is overwriting KernelCallbackTable field in the PEB of the victim | https://github.com/odzhan/injection/blob/master/kct |
| USERDATA                                      | &check; | Check if WPM target address is in conhost.exe range. If so check if any relevant function pointers from conhost match previously stored WPM address | https://github.com/odzhan/injection/blob/master/conhost |
| Ctrl-inject                                   | &check; | Detect if the attacker does WPM in victim's KernelBase.dll range   | Pinjectra |
| ALPC Callback                                 | &check; | Extract victim pid in NtConnectPort calls to ALPC port. For attacker-victim pid tuple check prior WPM calls and apply Floating code detection | Pinjectra |
| WNF Callback                                  | &check; | WPM followed by UpdateWNFStateData call   | https://github.com/odzhan/injection/tree/master/wnf |
| SetWindowsHook                                | &check; | Save module paths registered in NtUserSetWindowsHookEx hook. Later when a module matching this path loads in a different process, generate alert | MInjector |
| GhostWriting                                  | &check; | Detect if context is set (NtSetContextThread is called) on a previously suspended thread | Pinjectra |
| Service Control                               | &check; | WPM overwriting Service IDE of a process (service) | https://github.com/odzhan/injection/tree/master/svcctrl |
| Shellcode injection                           | &check; | New thread started from floating code. DLL path being written by WPM    | MInjector |
| Image Mapping                                 | &check; | Thread started from floating code. PE header being written by WPM. DLL path being written by WPM | MInjector |
| Thread Reuse                                  | &check; | Thread started from floating code. DLL path being written by WPM  | MInjector |


### Architecture Overview

![alt text](diagrams/FalconEye_Software_Architecture.png)

1. The driver is an on-demand load driver
2. The initialization includes setting up callbacks and syscall hooks via
   libinfinityhook
3. The callbacks maintain a map of Pids built from cross process activity such
   as OpenProcess but it is not limited to OpenProcess
4. Subsequent callbacks and syscall hooks use this Pid map to reduce the noise
   in processing. As a part of noise reduction, syscall hooks filter out same
process activity.
5. The detection logic is divided into subcategories namely - stateless (example:
   Atombombing), stateful (Unmap+Overwrite) and Floating code(Shellcode from
multiple techniques)
6. For stateful detections, syscall hooks record an ActionHistory which is
   implemented as a circular buffer. e.g. It records all the
NtWriteVirtualMemory calls where the caller process is different from the
target process.
7. The detection logic has common anomaly detection functionality such as
   floating code detection and detection for shellcode triggers in remote
processes. Both callbacks and syscall hooks invoke this common functionality
for actual detection.

NOTE: Our focus has been detection and not creating a performant
detection engine. We’ll continue on these efforts past the BlackHat
presentation.


## Files
```bash
.
├── src 
│   ├── FalconEye ---------------------------# FalconEye user and kernel space
│   └── libinfinityhook ---------------------# Kernel hook implementation
├── 2021BHASIA_FalconEye.pdf
└── README.md
```

## Getting Started

### Prerequisites
1. Windows 10 Build 1903/1909
2. Microsoft Visual Studio 2019 onwards
3. Virtualization Software such as VmWare, Hyper-V (Optional)

### Installation
#### Build
1. Open the solution with Visual Studio 2019
2. Select x64 as build platform
3. Build solution. This should generate FalconEye.sys binary under src\kernel\FalconEye\x64\Debug or src\kernel\FalconEye\x64\Release

#### Test Machine Setup
1. Install Windows 10 Build 1903/1909 in a VM
2. Configure VM for testing unsigned driver
 - Using bcdedit, disable integrity checks : ```BCDEDIT /set nointegritychecks ON```
3. Run DbgView from sysinternals in the VM or start a debugging connection using WinDbg.

### Usage
1. Copy FalconEye.sys to the Test Machine (Windows 10 VM)
2. Load FalconEye.sys as 'On Demand' load driver using OSR Loader or similar tools
3. Run injection test tools such as pinjectra, minjector or other samples
4. Monitor debug logs either via WinDbg or DbgView

## References
[InfinityHook, 2019](https://github.com/everdox/InfinityHook/)

[Itzik Kotler and Amit Klein. Process Injection Techniques - Gotta Catch Them All, Blackhat USA Briengs, 2019](https://www.blackhat.com/us-19/briefings/schedule/#process-injection-techniques---gotta-catch-them-all-16010)

[Pinjectra, 2019](https://github.com/SafeBreach-Labs/pinjectra/)

[Mapping-Injection, 2020](https://github.com/antonioCoco/Mapping-Injection)

[Atombombing: Brand new code injection for windows, 2016](https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows)

[Propagate - a new code injection trick, 2017](http://www.hexacorn.com/blog/2017/10/26/propagate-a-new-code-injection-trick/)

[Windows process injection: Extra window bytes, 2018](https://modexp.wordpress.com/2018/08/26/process-injection-ctray/)

[Pavel Asinovsky. Diving into zberp's unconventional process injection technique, 2016](https://securityintelligence.com/diving-into-zberps-unconventional-process-injection-technique/)

[Rotem Kerner. Ctrl-inject, 2018](https://blog.ensilo.com/ctrl-inject)

[Windows process injection: Consolewindowclass, 2018](https://modexp.wordpress.com/2018/09/12/process-injection-user-data/)

[Windows process injection: Windows notication facility, 2018](https://modexp.wordpress.com/2019/06/15/4083/)

[A paradox: Writing to another process without openning it nor actually writing to it, 2007](http://blog.txipinet.com/2007/04/05/69-a-paradox-writing-to-another-process-without-openning-it-nor-actually-writing-to-it/)

[Windows process injection: Service control handler, 2018](https://modexp.wordpress.com/2018/08/30/windows-process-injection-control-handler/)

[Marcos Oviedo. Memhunter - Automated hunting of memory resident malware at scale. Defcon Demo Labs, 2019](https://github.com/marcosd4h/memhunter)

## License Terms
FalconEye is licensed to you under [Apache 2.0](COPYING) open source license. 
