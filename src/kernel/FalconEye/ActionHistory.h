#pragma once
#define NTWVM_BUFFER_SIZE 512
#define NTUNMVS_BUFFER_SIZE     512
#define NTST_BUFFER_SIZE        512
#define NTUSERSWLP_BUFFER_SIZE  1024
#define NTUSERSP_BUFFER_SIZE    1024
#define NTUSERSWHEX_BUFFER_SIZE 512
#define NTUWNFSD_BUFFER_SIZE    512

#define NTWVM_DATA_COPY_SIZE    300

typedef struct _NtWVMEntry {
    ULONG64   callerPid;
    ULONG64   targetPid;
    PVOID   targetAddr;
    PVOID   localBuffer;
    ULONG   bufferSize;
    CHAR    initialData[NTWVM_DATA_COPY_SIZE];
}NtWVMEntry;

typedef struct _NtUnMVSEntry {
    ULONG   callerPid;
    ULONG   targetPid;
    PVOID   baseAddr;
}NtUnMVSEntry;

typedef struct _NtSTEntry {
    ULONG   callerPid;
    ULONG   targetPid;
    ULONG   targetTid;
}NtSTEntry;

typedef struct _NtUserSWLPEntry {
    HWND hWnd;
    DWORD Index;
    LONG_PTR NewValue;
}NtUserSWLPEntry;

typedef struct _NtUserSPEntry {
    HWND hWnd;
    ATOM Atom;
    HANDLE Data;
}NtUserSPEntry;

typedef struct _NtUserSWHExEntry {
    ULONG64     Pid;
    HINSTANCE   Mod;
    DWORD       ThreadId;
    int         HookId;
    HOOKPROC    HookProc;
    WCHAR       ModuleName[260];
}NtUserSWHExEntry;

typedef struct _NtUWnfSDEntry {
    ULONG CallerPid;
    VOID* Buffer;
    ULONG Length;
}NtUWnfSDEntry;

BOOLEAN InitActionHistory();
BOOLEAN CleanupActionHistory();
BOOLEAN AddNtWriteVirtualMemoryEntry(
    ULONG   callerPid,
    ULONG   targetPid,
    PVOID   targetAddr,
    PVOID   localBuffer,
    ULONG   bufferSize);

BOOLEAN AddNtUnmapViewOfSectionEntry(
    ULONG   callerPid,
    ULONG   targetPid,
    PVOID   baseAddr
);

BOOLEAN AddNtSuspendThreadEntry(
    ULONG   callerPid,
    ULONG   targetPid,
    ULONG   targetTid
);

BOOLEAN AddNtUserSetWindowLongPtrEntry(
    HWND hWnd,
    DWORD Index,
    LONG_PTR NewValue
);
NtUserSWLPEntry* FindNtUserSetWindowLongPtrEntry(HWND hWnd);

BOOLEAN AddNtUserSetPropEntry(
    HWND hWnd,
    ATOM Atom,
    HANDLE Data
);

NtUserSPEntry* FindNtSetWindowLongPtrEntry(HWND hWnd);

NtWVMEntry* FindNtWriteVirtualMemoryEntry(ULONG64 callerPid, PVOID baseAddress);
NtWVMEntry* FindNtWriteVirtualMemoryEntryByAddress(ULONG64 callerPid, PVOID baseAddress);

BOOLEAN AddNtUserSetWindowsHookExEntry(
    ULONG64   Pid,
    HINSTANCE Mod,
    PUNICODE_STRING UnsafeModuleName,
    DWORD ThreadId,
    int HookId,
    HOOKPROC HookProc
);

NtUserSWHExEntry* FindNtSetWindowHookExEntry(WCHAR* pModule);

BOOLEAN AddNtUpdateWnfStateDataEntry(
    ULONG CallerPid,
    VOID* Buffer,
    ULONG Length);

NtUWnfSDEntry* FindNtUpdateWnfStateDataEntry(ULONG CallerPid);

BOOLEAN CheckWriteSuspendHistoryForSetThrCtx(
    ULONG callerPid,
    ULONG targetPid,
    ULONG targetTid);

BOOLEAN CheckPriorWnfStateUpdate(
    ULONG callerPid, 
    ULONG targetPid,
    HANDLE targetPs);
