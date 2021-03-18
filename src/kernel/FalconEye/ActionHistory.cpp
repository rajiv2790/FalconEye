#include "stdafx.h"
#include "ActionHistory.h"

NtWVMEntry* NtWVMBuffer = NULL;
SIZE_T      freeNtWVMIdx = 0;
ERESOURCE   NtWVMLock;
ULONG       ActionHistoryTag = 0xfffe;

BOOLEAN InitNtWVMHistory()
{
    NtWVMBuffer = (NtWVMEntry*)ExAllocatePoolWithTag(
        NonPagedPool,
        NTWVM_BUFFER_SIZE * sizeof(NtWVMEntry),
        ActionHistoryTag
    );
    if (NULL == NtWVMBuffer) {
        return FALSE;
    }
    ExInitializeResourceLite(&NtWVMLock);
    return TRUE;
}

BOOLEAN InitActionHistory()
{
    InitNtWVMHistory();
    return TRUE;
}

BOOLEAN AddNtWriteVirtualMemoryEntry(
    ULONG   callerPid,
    ULONG   targetPid,
    PVOID   targetAddr,
    PVOID   localBuffer,
    ULONG   bufferSize
)
{
    if (FALSE == ExAcquireResourceExclusiveLite(&NtWVMLock, TRUE)) {
        return FALSE;
    }
    NtWVMBuffer[freeNtWVMIdx] = { callerPid, targetPid, targetAddr, localBuffer, bufferSize };
    freeNtWVMIdx = (freeNtWVMIdx + 1) % NTWVM_BUFFER_SIZE;
    ExReleaseResourceLite(&NtWVMLock);
    return TRUE;
}

// Caller must deallocate NtWVMEntry
NtWVMEntry* FindNtWriteVirtualMemoryEntry(ULONG callerPid, ULONG targetPid)
{
    NtWVMEntry* entry = NULL;
    if (FALSE == ExAcquireResourceExclusiveLite(&NtWVMLock, TRUE)) {
        return FALSE;
    }
    entry = (NtWVMEntry*)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(NtWVMEntry),
        ActionHistoryTag);
    if (NULL == entry) {
        ExReleaseResourceLite(&NtWVMLock);
        return FALSE;
    }
    for (auto i = 0; i < NTWVM_BUFFER_SIZE; i++) {
        if (callerPid == NtWVMBuffer[i].callerPid && targetPid == NtWVMBuffer[i].targetPid) {
            //entry = &NtWVMBuffer[i];
            RtlCopyMemory(entry, &NtWVMBuffer[i], sizeof(NtWVMEntry));
            break;
        }
    }
    ExReleaseResourceLite(&NtWVMLock);
    return entry;
}