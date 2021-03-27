#pragma once

// kernel32
#define GLOBALADDATOMA_OFFSET   0x00107c0
#define GLOBALADDATOMW_OFFSET   0x00108b0
#define GLOBALADDATOMEXA_OFFSET 0x0052b70
#define GLOBALADDATOMEXW_OFFSET 0x00105c0

// kernelbase
#define LOADLIBA_OFFSET     0x00566f0
#define LOADLIBW_OFFSET     0x007aba0

enum {
    eUnknownApi = 0,
    eGlobalAddAtom,
    eLoadLibrary,
};

ULONG GetProcessIdByHandle(HANDLE process);
ULONG GetThreadIdByHandle(HANDLE thread);
ULONG GetProcessIdByThreadHandle(HANDLE thread);
HANDLE GetProcessHandleByThreadHandle(HANDLE thread);
BOOLEAN GetActionPids(HANDLE ProcessHandle, ULONG* pCallerPid, ULONG* pTargetPid);
BOOLEAN GetActionPidsByThread(HANDLE ThreadHandle, ULONG* pCallerPid, ULONG* pTargetPid);