#include <excpt.h>
#include "stdafx.h"
#include "NtDefs.h"
#include "ActionHistory.h"
#include "Helper.h"
#include "entry.h"

NtWVMEntry* NtWVMBuffer = NULL;
SIZE_T      freeNtWVMIdx = 0;
ERESOURCE   NtWVMLock;

NtUnMVSEntry* NtUnMVSBuffer = NULL;
SIZE_T      freeNtUnMVSIdx = 0;
ERESOURCE   NtUnMVSLock;

NtSTEntry*  NtSTBuffer = NULL;
SIZE_T      freeNtSTIdx = 0;
ERESOURCE   NtSTLock;

NtUserSWLPEntry* NtUserSWLPBuffer = NULL;
SIZE_T      freeNtUserSWLPIdx = 0;
ERESOURCE   NtUserSWLPLock;

NtUserSPEntry* NtUserSPBuffer = NULL;
SIZE_T      freeNtUserSPIdx = 0;
ERESOURCE   NtUserSPLock;

NtUserSWHExEntry* NtUserSWHExBuffer = NULL;
SIZE_T      freeNtUserSWHExIdx = 0;
ERESOURCE   NtUserSWHExLock;

NtUWnfSDEntry* NtUWnfSDBuffer = NULL;
SIZE_T      freeNtUWnfSDIdx = 0;
ERESOURCE   NtUWnfSDLock;

extern "C" {
    NTSTATUS ReadWVMData(PVOID localBuffer, ULONG bufferSize, PCHAR targetBuffer);
}

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

BOOLEAN InitNtUnMVSHistory()
{
    NtUnMVSBuffer = (NtUnMVSEntry*)ExAllocatePoolWithTag(
        NonPagedPool,
        NTUNMVS_BUFFER_SIZE * sizeof(NtUnMVSEntry),
        ActionHistoryTag
    );
    if (NULL == NtUnMVSBuffer) {
        return FALSE;
    }
    ExInitializeResourceLite(&NtUnMVSLock);
    return TRUE;
}

BOOLEAN InitNtSTHistory()
{
    NtSTBuffer = (NtSTEntry*)ExAllocatePoolWithTag(
        NonPagedPool,
        NTST_BUFFER_SIZE * sizeof(NtSTEntry),
        ActionHistoryTag
    );
    if (NULL == NtSTBuffer) {
        return FALSE;
    }
    ExInitializeResourceLite(&NtSTLock);
    return TRUE;
}

BOOLEAN InitNtUserSWLPHistory()
{
    NtUserSWLPBuffer = (NtUserSWLPEntry*)ExAllocatePoolWithTag(
        NonPagedPool,
        NTUSERSWLP_BUFFER_SIZE * sizeof(NtUserSWLPEntry),
        ActionHistoryTag
    );
    if (NULL == NtUserSWLPBuffer) {
        return FALSE;
    }
    ExInitializeResourceLite(&NtUserSWLPLock);
    return TRUE;
}

BOOLEAN InitNtUserSPHistory()
{
    NtUserSPBuffer = (NtUserSPEntry*)ExAllocatePoolWithTag(
        NonPagedPool,
        NTUSERSP_BUFFER_SIZE * sizeof(NtUserSPEntry),
        ActionHistoryTag
    );
    if (NULL == NtUserSPBuffer) {
        return FALSE;
    }
    ExInitializeResourceLite(&NtUserSPLock);
    return TRUE;
}

BOOLEAN InitNtUserSWHExHistory()
{
    NtUserSWHExBuffer = (NtUserSWHExEntry*)ExAllocatePoolWithTag(
        NonPagedPool,
        NTUSERSWHEX_BUFFER_SIZE * sizeof(NtUserSWHExEntry),
        ActionHistoryTag
    );
    if (NULL == NtUserSWHExBuffer) {
        return FALSE;
    }
    ExInitializeResourceLite(&NtUserSWHExLock);
    return TRUE;
}

BOOLEAN InitNtUWnfSDHistory()
{
    NtUWnfSDBuffer = (NtUWnfSDEntry*)ExAllocatePoolWithTag(
        NonPagedPool,
        NTUWNFSD_BUFFER_SIZE * sizeof(NtUWnfSDEntry),
        ActionHistoryTag
    );
    if (NULL == NtUWnfSDBuffer) {
        return FALSE;
    }
    ExInitializeResourceLite(&NtUWnfSDLock);
    return TRUE;
}

BOOLEAN CleanupActionHistory()
{
    ExDeleteResourceLite(&NtWVMLock);
    ExDeleteResourceLite(&NtUnMVSLock);
    ExDeleteResourceLite(&NtSTLock);
    ExDeleteResourceLite(&NtUserSWLPLock);
    ExDeleteResourceLite(&NtUserSPLock);
    ExDeleteResourceLite(&NtUserSWHExLock);
    ExDeleteResourceLite(&NtUWnfSDLock);
    return TRUE;
}

BOOLEAN InitActionHistory()
{
    InitNtWVMHistory();
    InitNtUnMVSHistory();
    InitNtSTHistory();
    InitNtUserSWLPHistory();
    InitNtUserSPHistory();
    InitNtUserSWHExHistory();
    InitNtUWnfSDHistory();
    return TRUE;
}

BOOLEAN CheckForServiceIDE(
    CHAR* buffer,
    size_t size,
    ULONG   callerPid,
    ULONG   targetPid)
{
    if (NULL == buffer || 0 == size) {
        return FALSE;
    }
    ULONG64 svcName, svcRealName;
    svcName = *((ULONG*)buffer);
    svcRealName = *((ULONG*)(buffer + sizeof(ULONG64)));
    if (0 != svcName && svcName == svcRealName) {
        kprintf("%llu %llu \n", svcName, svcRealName);
    }
    PINTERNAL_DISPATCH_ENTRY ide = (PINTERNAL_DISPATCH_ENTRY)buffer;
    if (NULL != ide->ServiceName
        && ide->ServiceName == ide->ServiceRealName)
    {
        if (ide->ServiceFlags == 4 && NULL != ide->ControlHandler) {
            alertf("[+] FalconEye: **************************Alert**************************: \n"
                "Attacker pid %llu overwriting Service IDE in victim pid %llu\n",
                callerPid,
                targetPid);
            alertf("\n");
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN IsAddrInConhostRange(PVOID64 addr)
{
    if (conhostBase < addr &&
        conhostEnd > addr)
    {
        return TRUE;
    }
    return FALSE;
}
BOOLEAN CheckConhostVtableOverwrite(
    ULONG callerPid, 
    ULONG targetPid, 
    CHAR* targetBuffer)
{
    ConsoleWindow* cw = (ConsoleWindow*)targetBuffer;
    if (NULL != cw->EnableBothScrollBars && NULL != cw->GetWindowHandle) {
        if (!IsAddrInConhostRange((PVOID64)cw->EnableBothScrollBars)
            && !IsAddrInConhostRange((PVOID64)cw->GetWindowHandle))
        {
            return FALSE;
        }
    }

    NtWVMEntry* wvmEntry = FindNtWriteVirtualMemoryEntryByAddress(
        callerPid,
        (PVOID)cw->GetWindowHandle);
    if (NULL != wvmEntry) {
        alertf("[+] FalconEye: **************************Alert**************************: \n"
            "Attacker pid %d likely overwriting Console GetWindowHandle function in victim pid %d\n",
            callerPid,
            targetPid);
        alertf("\n");
        ExFreePool(wvmEntry);
        return TRUE;
    }
    
    return FALSE;
}

BOOLEAN AddNtWriteVirtualMemoryEntry(
    ULONG   callerPid,
    ULONG   targetPid,
    PVOID   targetAddr,
    PVOID   localBuffer,
    ULONG   bufferSize
)
{
    CHAR targetBuffer[NTWVM_DATA_COPY_SIZE] = { 0 };
    ReadWVMData(localBuffer, bufferSize, targetBuffer);
    if (FALSE == ExAcquireResourceExclusiveLite(&NtWVMLock, TRUE)) {
        return FALSE;
    }
    NtWVMBuffer[freeNtWVMIdx] = { callerPid, targetPid, targetAddr, localBuffer, bufferSize };
    RtlCopyMemory(NtWVMBuffer[freeNtWVMIdx].initialData, targetBuffer, NTWVM_DATA_COPY_SIZE);
    freeNtWVMIdx = (freeNtWVMIdx + 1) % NTWVM_BUFFER_SIZE;
    ExReleaseResourceLite(&NtWVMLock);
    if (IsValidPEHeader(targetBuffer, NTWVM_DATA_COPY_SIZE)) {
        alertf("FalconEye: DetourNtWriteVirtualMemory: callerPid %d targetPid %d BaseAddr %p.\n",
            callerPid, targetPid, targetAddr);
        alertf("[+] FalconEye: **************************Alert**************************: \n"
            "Attacker pid %llu writing PE Header in victim pid %llu at address %p\n",
            callerPid,
            targetPid,
            targetAddr);
        alertf("\n");
    }
    IsValidDllPath(targetBuffer, NTWVM_DATA_COPY_SIZE);
    CheckForServiceIDE(targetBuffer, NTWVM_DATA_COPY_SIZE, callerPid, targetPid);
    CheckConhostVtableOverwrite(callerPid, targetPid, targetBuffer);
    return TRUE;
}

// Caller must deallocate NtWVMEntry
// Find by caller pid and target pid
NtWVMEntry* FindNtWriteVirtualMemoryEntry(ULONG64 callerPid, ULONG targetPid)
{
    NtWVMEntry* entry = NULL;
    if (FALSE == ExAcquireResourceExclusiveLite(&NtWVMLock, TRUE)) {
        return NULL;
    }

    for (auto i = 0; i < NTWVM_BUFFER_SIZE; i++) {
        if (callerPid == NtWVMBuffer[i].callerPid && targetPid == NtWVMBuffer[i].targetPid) {
            entry = (NtWVMEntry*)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(NtWVMEntry),
                ActionHistoryTag);
            if (NULL == entry) {
                ExReleaseResourceLite(&NtWVMLock);
                return NULL;
            }
            RtlCopyMemory(entry, &NtWVMBuffer[i], sizeof(NtWVMEntry));
            break;
        }
    }
    ExReleaseResourceLite(&NtWVMLock);
    return entry;
}

// Caller must deallocate NtWVMEntry
// Find by caller pid and target address
NtWVMEntry* FindNtWriteVirtualMemoryEntryByAddress(ULONG64 callerPid, PVOID baseAddress)
{
    NtWVMEntry* entry = NULL;
    if (FALSE == ExAcquireResourceExclusiveLite(&NtWVMLock, TRUE)) {
        return NULL;
    }

    for (auto i = 0; i < NTWVM_BUFFER_SIZE; i++) {
        if (callerPid == NtWVMBuffer[i].callerPid && baseAddress == NtWVMBuffer[i].targetAddr) {
            entry = (NtWVMEntry*)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(NtWVMEntry),
                ActionHistoryTag);
            if (NULL == entry) {
                ExReleaseResourceLite(&NtWVMLock);
                return NULL;
            }
            RtlCopyMemory(entry, &NtWVMBuffer[i], sizeof(NtWVMEntry));
            break;
        }
    }
    ExReleaseResourceLite(&NtWVMLock);
    return entry;
}

BOOLEAN AddNtUnmapViewOfSectionEntry(
    ULONG   callerPid,
    ULONG   targetPid,
    PVOID   baseAddr
)
{
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUnMVSLock, TRUE)) {
        return FALSE;
    }
    NtUnMVSBuffer[freeNtUnMVSIdx] = { callerPid, targetPid, baseAddr };
    freeNtUnMVSIdx = (freeNtUnMVSIdx + 1) % NTWVM_BUFFER_SIZE;
    ExReleaseResourceLite(&NtUnMVSLock);
    return TRUE;
}

// Caller must deallocate NtWVMEntry
NtUnMVSEntry* FindNtUnmapViewOfSectionEntry(ULONG callerPid, ULONG targetPid)
{
    NtUnMVSEntry* entry = NULL;
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUnMVSLock, TRUE)) {
        return NULL;
    }

    for (auto i = 0; i < NTUNMVS_BUFFER_SIZE; i++) {
        if (callerPid == NtUnMVSBuffer[i].callerPid && targetPid == NtUnMVSBuffer[i].targetPid) {
            entry = (NtUnMVSEntry*)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(NtUnMVSEntry),
                ActionHistoryTag);
            if (NULL == entry) {
                ExReleaseResourceLite(&NtUnMVSLock);
                return NULL;
            }
            RtlCopyMemory(entry, &NtUnMVSBuffer[i], sizeof(NtUnMVSEntry));
            break;
        }
    }
    ExReleaseResourceLite(&NtUnMVSLock);
    return entry;
}

BOOLEAN AddNtSuspendThreadEntry(
    ULONG   callerPid,
    ULONG   targetPid,
    ULONG   targetTid
)
{
    if (FALSE == ExAcquireResourceExclusiveLite(&NtSTLock, TRUE)) {
        return FALSE;
    }
    NtSTBuffer[freeNtSTIdx] = { callerPid, targetPid, targetTid };
    freeNtSTIdx = (freeNtSTIdx + 1) % NTST_BUFFER_SIZE;
    ExReleaseResourceLite(&NtSTLock);
    return TRUE;
}

// Caller must deallocate NtWVMEntry
NtSTEntry* FindNtSuspendThreadEntry(ULONG callerPid, ULONG targetPid)
{
    NtSTEntry* entry = NULL;
    if (FALSE == ExAcquireResourceExclusiveLite(&NtSTLock, TRUE)) {
        return NULL;
    }

    for (auto i = 0; i < NTST_BUFFER_SIZE; i++) {
        if (callerPid == NtSTBuffer[i].callerPid && targetPid == NtSTBuffer[i].targetPid) {
            entry = (NtSTEntry*)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(NtSTEntry),
                ActionHistoryTag);
            if (NULL == entry) {
                ExReleaseResourceLite(&NtSTLock);
                return NULL;
            }
            RtlCopyMemory(entry, &NtSTBuffer[i], sizeof(NtSTEntry));
            break;
        }
    }
    ExReleaseResourceLite(&NtSTLock);
    return entry;
}

BOOLEAN AddNtUserSetWindowLongPtrEntry(
    HWND hWnd,
    DWORD Index,
    LONG_PTR NewValue
)
{
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUserSWLPLock, TRUE)) {
        return FALSE;
    }
    NtUserSWLPBuffer[freeNtUserSWLPIdx] = { hWnd, Index, NewValue };
    freeNtUserSWLPIdx = (freeNtUserSWLPIdx + 1) % NTUSERSWLP_BUFFER_SIZE;
    ExReleaseResourceLite(&NtUserSWLPLock);
    return TRUE;
}

// Caller must deallocate NtUserSWLPEntry
NtUserSWLPEntry* FindNtUserSetWindowLongPtrEntry(HWND hWnd)
{
    NtUserSWLPEntry* entry = NULL;
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUserSWLPLock, TRUE)) {
        return NULL;
    }

    for (auto i = 0; i < NTUSERSWLP_BUFFER_SIZE; i++) {
        if (hWnd == NtUserSWLPBuffer[i].hWnd) {
            entry = (NtUserSWLPEntry*)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(NtUserSWLPEntry),
                ActionHistoryTag);
            if (NULL == entry) {
                ExReleaseResourceLite(&NtUserSWLPLock);
                return NULL;
            }
            RtlCopyMemory(entry, &NtUserSWLPBuffer[i], sizeof(NtUserSWLPEntry));
            break;
        }
    }
    ExReleaseResourceLite(&NtUserSWLPLock);
    return entry;
}

BOOLEAN AddNtUserSetPropEntry(
    HWND hWnd,
    ATOM Atom,
    HANDLE Data
)
{
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUserSPLock, TRUE)) {
        return FALSE;
    }
    NtUserSPBuffer[freeNtUserSPIdx] = { hWnd, Atom, Data };
    freeNtUserSPIdx = (freeNtUserSPIdx + 1) % NTUSERSP_BUFFER_SIZE;
    ExReleaseResourceLite(&NtUserSPLock);
    return TRUE;
}

// Caller must deallocate NtUserSPEntry
NtUserSPEntry* FindNtSetWindowLongPtrEntry(HWND hWnd)
{
    NtUserSPEntry* entry = NULL;
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUserSPLock, TRUE)) {
        return NULL;
    }

    for (auto i = 0; i < NTUSERSP_BUFFER_SIZE; i++) {
        if (hWnd == NtUserSPBuffer[i].hWnd) {
            entry = (NtUserSPEntry*)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(NtUserSPEntry),
                ActionHistoryTag);
            if (NULL == entry) {
                ExReleaseResourceLite(&NtUserSPLock);
                return NULL;
            }
            RtlCopyMemory(entry, &NtUserSPBuffer[i], sizeof(NtUserSPEntry));
            break;
        }
    }
    ExReleaseResourceLite(&NtUserSPLock);
    return entry;
}



BOOLEAN AddNtUserSetWindowsHookExEntry(
    ULONG64   Pid,
    HINSTANCE Mod,
    PUNICODE_STRING UnsafeModuleName,
    DWORD ThreadId,
    int HookId,
    HOOKPROC HookProc
)
{
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUserSWHExLock, TRUE)) {
        return FALSE;
    }
    NtUserSWHExBuffer[freeNtUserSWHExIdx].Pid = Pid;
    NtUserSWHExBuffer[freeNtUserSWHExIdx].Mod = Mod;
    NtUserSWHExBuffer[freeNtUserSWHExIdx].ThreadId = ThreadId;
    NtUserSWHExBuffer[freeNtUserSWHExIdx].HookId = HookId;
    NtUserSWHExBuffer[freeNtUserSWHExIdx].HookProc = HookProc;

    RtlZeroMemory(NtUserSWHExBuffer[freeNtUserSWHExIdx].ModuleName, MAX_PATH * sizeof(WCHAR));
    if (NULL != UnsafeModuleName->Buffer) {
        WCHAR dosPath[MAX_PATH] = { 0 };
        RtlCopyMemory(dosPath, UnsafeModuleName->Buffer, UnsafeModuleName->Length);
        ConvertDosPathToDevicePath(dosPath, NtUserSWHExBuffer[freeNtUserSWHExIdx].ModuleName);
    }
    freeNtUserSWHExIdx = (freeNtUserSWHExIdx + 1) % NTUSERSWHEX_BUFFER_SIZE;
    ExReleaseResourceLite(&NtUserSWHExLock);
    return TRUE;
}

// Caller must deallocate NtUserSWHExEntry
NtUserSWHExEntry* FindNtSetWindowHookExEntry(WCHAR *pModule)
{
    NtUserSWHExEntry* entry = NULL;
    if (NULL == pModule) {
        return NULL;
    }
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUserSWHExLock, TRUE)) {
        return NULL;
    }
    for (auto i = 0; i < NTUSERSWHEX_BUFFER_SIZE; i++) {
        if (0 == wcscmp (NtUserSWHExBuffer[i].ModuleName, pModule)) {
            entry = (NtUserSWHExEntry*)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(NtUserSWHExEntry),
                ActionHistoryTag);
            if (NULL == entry) {
                ExReleaseResourceLite(&NtUserSWHExLock);
                return NULL;
            }
            RtlCopyMemory(entry, &NtUserSWHExBuffer[i], sizeof(NtUserSWHExEntry));
            break;
        }
    }
    ExReleaseResourceLite(&NtUserSWHExLock);
    return entry;
}

BOOLEAN AddNtUpdateWnfStateDataEntry(
    ULONG CallerPid,
    VOID* Buffer,
    ULONG Length
)
{
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUWnfSDLock, TRUE)) {
        return FALSE;
    }
    NtUWnfSDBuffer[freeNtUWnfSDIdx] = { CallerPid, Buffer, Length };
    freeNtUWnfSDIdx = (freeNtUWnfSDIdx + 1) % NTUWNFSD_BUFFER_SIZE;
    ExReleaseResourceLite(&NtUWnfSDLock);
    return TRUE;
}

// Caller must deallocate NtUWnfSDEntry
NtUWnfSDEntry* FindNtUpdateWnfStateDataEntry(ULONG CallerPid)
{
    NtUWnfSDEntry* entry = NULL;
    if (FALSE == ExAcquireResourceExclusiveLite(&NtUWnfSDLock, TRUE)) {
        return NULL;
    }

    for (auto i = 0; i < NTUWNFSD_BUFFER_SIZE; i++) {
        if (CallerPid == NtUWnfSDBuffer[i].CallerPid) {
            entry = (NtUWnfSDEntry*)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(NtUWnfSDEntry),
                ActionHistoryTag);
            if (NULL == entry) {
                ExReleaseResourceLite(&NtUWnfSDLock);
                return NULL;
            }
            RtlCopyMemory(entry, &NtUWnfSDBuffer[i], sizeof(NtUWnfSDEntry));
            break;
        }
    }
    ExReleaseResourceLite(&NtUWnfSDLock);
    return entry;
}

BOOLEAN CheckWriteSuspendHistoryForSetThrCtx(
    ULONG callerPid, 
    ULONG targetPid,
    ULONG targetTid)
{
    NtSTEntry* stEntry = FindNtSuspendThreadEntry(callerPid, targetPid);
    if (NULL != stEntry) {
        if (targetTid == stEntry->targetTid) {
            alertf("[+] FalconEye: **************************Alert**************************: \n"
                "Attacker pid %d setting context for suspended thread %d in victim pid %d \n",
                callerPid, targetTid, targetPid);
        }
        ExFreePool(stEntry);
    }
    else {
        return false;
    }
    return true;
}

BOOLEAN isPidExplorer(HANDLE process)
{
    BOOLEAN ret = FALSE;
    ULONG size = 512; // Arbitrary, assuming that the process file name should fit
    UNICODE_STRING explorer = RTL_CONSTANT_STRING(L"explorer.exe");

    PUNICODE_STRING filename = (PUNICODE_STRING)ExAllocatePool(NonPagedPool, size);
    if (filename == nullptr)
    {
        //Could not allocate memory to store filename
        return FALSE;
    }
    if (!ZwQueryInformationProcess(process,
        ProcessImageFileName, // 27
        filename,
        size - sizeof(WCHAR), //Ensure string will be NULL terminated
        NULL))
    {
        if (compareFilename(filename, explorer, FALSE) == 0)
        {
                // kprintf("[+] falconeye: Ignoring OpenProcess for %wZ\n", filename);
                ret = TRUE;
        }
    }
    return ret;
}

BOOLEAN CheckPriorWnfStateUpdate(
    ULONG callerPid, 
    ULONG targetPid,
    HANDLE targetPs)
{
    // check for prior memory writes
    NtWVMEntry* wvmEntry = FindNtWriteVirtualMemoryEntry(callerPid, targetPid);
    if (NULL == wvmEntry) {
        return FALSE;
    }
    ExFreePool(wvmEntry);

    NtUWnfSDEntry* entry = FindNtUpdateWnfStateDataEntry(callerPid);
    if (NULL != entry) {
        if (NULL == entry->Buffer && 0 == entry->Length) {
            if (isPidExplorer(targetPs)) {
                alertf("[+] FalconEye: **************************Alert**************************: \n"
                    "Attacker pid %d updating WNF state in victim pid %d \n",
                    callerPid, targetPid);
            }
        }
        ExFreePool(entry);
    }
    else {
        return false;
    }
    return true;
}