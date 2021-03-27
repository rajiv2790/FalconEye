#pragma once
#define NTWVM_BUFFER_SIZE 512
#define NTUNMVS_BUFFER_SIZE     512
#define NTST_BUFFER_SIZE        512

#define NTWVM_DATA_COPY_SIZE    300

typedef struct _NtWVMEntry {
    ULONG   callerPid;
    ULONG   targetPid;
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


BOOLEAN InitActionHistory();
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