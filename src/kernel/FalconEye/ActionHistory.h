#pragma once
#define NTWVM_BUFFER_SIZE 512


typedef struct _NtWVMEntry {
    ULONG   callerPid;
    ULONG   targetPid;
    PVOID   targetAddr;
    PVOID   localBuffer;
    ULONG   bufferSize;
}NtWVMEntry;

BOOLEAN InitActionHistory();
BOOLEAN AddNtWriteVirtualMemoryEntry(
    ULONG   callerPid,
    ULONG   targetPid,
    PVOID   targetAddr,
    PVOID   localBuffer,
    ULONG   bufferSize);
