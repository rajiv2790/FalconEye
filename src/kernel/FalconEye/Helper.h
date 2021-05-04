#pragma once

// kernel32
#define GLOBALGETATOMA_OFFSET   0x0052bb0
#define GLOBALGETATOMW_OFFSET   0x0010610

#define GLOBALADDATOMA_OFFSET   0x00107c0
#define GLOBALADDATOMW_OFFSET   0x00108b0
#define GLOBALADDATOMEXA_OFFSET 0x0052b70
#define GLOBALADDATOMEXW_OFFSET 0x00105c0

#define LOADLIBA_OFFSET     0x001ebb0 // 0x00566f0
#define LOADLIBW_OFFSET     0x001e540 // 0x007aba0
#define LOADLIBEXW_OFFSET   0x001a200
#define LOADLIBEXA_OFFSET   0x001e550

#define GETPROC_OFFSET      0x001a360
#define SETTHREADCTX_OFFSET 0x0036a30

#define MAX_DLL_START_OFFSET  16 * sizeof(WCHAR)
#define MAX_PATH                260
#define MAX_DEVICE_LEN          30
#define MAX_VOL_DEVICE_ENTRIES  10
#define FE_HELPER_TAG      'eFeH'

enum {
    eUnknownApi = 0,
    eGlobalGetAtom,
    eGlobalAddAtom,
    eLoadLibrary,
    eSetThreadCtx,
    eGetProcAddr
};

typedef struct _VolDeviceEntry {
    WCHAR   volumeLetter;
    WCHAR   device[MAX_DEVICE_LEN];
}VolDeviceEntry;

extern PVOID64 kernel32Base;
extern PVOID64 ntdllBase;
extern PVOID64 kernelbaseBase;
extern PVOID64 kernelbaseEnd;
ULONG GetProcessIdByHandle(HANDLE process);
ULONG GetThreadIdByHandle(HANDLE thread);
ULONG GetProcessIdByThreadHandle(HANDLE thread);
HANDLE GetProcessHandleByThreadHandle(HANDLE thread);
BOOLEAN GetActionPids(HANDLE ProcessHandle, ULONG* pCallerPid, ULONG* pTargetPid);
BOOLEAN GetActionPidsByThread(HANDLE ThreadHandle, ULONG* pCallerPid, ULONG* pTargetPid);
ULONG IsKnownAPIOffset(PCHAR pAddr);
BOOLEAN IsAddressInKernelBase(PCHAR pAddr);
BOOLEAN IsValidPEHeader(CHAR* buffer, size_t size);
BOOLEAN IsValidDllPath(CHAR* buffer, size_t size);
BOOLEAN GetVolumeList();
BOOLEAN GetDeviceForVolume(WCHAR volume, PWCHAR device);
BOOLEAN ConvertDosPathToDevicePath(PWCHAR dosPath, PWCHAR devicePath);