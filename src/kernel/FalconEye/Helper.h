#pragma once

// kernel32
#define GLOBALGETATOMA_OFFSET   0x0052bb0
#define GLOBALGETATOMW_OFFSET   0x0010610

#define GLOBALADDATOMA_OFFSET   0x00107c0
#define GLOBALADDATOMW_OFFSET   0x00108b0
#define GLOBALADDATOMEXA_OFFSET 0x0052b70
#define GLOBALADDATOMEXW_OFFSET 0x00105c0

// kernelbase
#define LOADLIBA_OFFSET     0x001ebb0 // 0x00566f0
#define LOADLIBW_OFFSET     0x001e540 // 0x007aba0
#define LOADLIBEXW_OFFSET   0x001a200
#define LOADLIBEXA_OFFSET   0x001e550

enum {
    eUnknownApi = 0,
    eGlobalGetAtom,
    eGlobalAddAtom,
    eLoadLibrary,
};

ULONG GetProcessIdByHandle(HANDLE process);
ULONG GetThreadIdByHandle(HANDLE thread);
ULONG GetProcessIdByThreadHandle(HANDLE thread);
HANDLE GetProcessHandleByThreadHandle(HANDLE thread);
BOOLEAN GetActionPids(HANDLE ProcessHandle, ULONG* pCallerPid, ULONG* pTargetPid);
BOOLEAN GetActionPidsByThread(HANDLE ThreadHandle, ULONG* pCallerPid, ULONG* pTargetPid);
ULONG IsKnownAPIOffset(PCHAR pAddr);