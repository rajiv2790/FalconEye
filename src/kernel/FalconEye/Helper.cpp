#include "stdafx.h"
#include "Helper.h"
extern PVOID64 kernel32Base;

ULONG GetProcessIdByHandle(HANDLE process)
{
    PEPROCESS   pProc = NULL;

    NTSTATUS status = ObReferenceObjectByHandle(
        process,
        GENERIC_READ,
        *PsProcessType,
        KernelMode,
        (PVOID*)&pProc,
        NULL);
    if (STATUS_SUCCESS == status && NULL != pProc) {
        HANDLE proc = PsGetProcessId(pProc);
        ObDereferenceObject(pProc);
        return (ULONG)((LONGLONG)proc & 0xffffffff);
    }
    if (NULL != pProc) {
        ObDereferenceObject(pProc);
    }
    return 0;
}

ULONG GetThreadIdByHandle(HANDLE thread)
{
    PETHREAD    pThr = NULL;

    NTSTATUS status = ObReferenceObjectByHandle(
        thread,
        GENERIC_READ,
        *PsThreadType,
        KernelMode,
        (PVOID*)&pThr,
        NULL);
    if (STATUS_SUCCESS == status && NULL != pThr) {
        HANDLE thr = PsGetThreadId(pThr);
        ObDereferenceObject(pThr);
        return (ULONG)((LONGLONG)thr & 0xffffffff);
    }
    if (NULL != pThr) {
        ObDereferenceObject(pThr);
    }
    return 0;
}

HANDLE GetProcessHandleByThreadHandle (HANDLE thread)
{
    PETHREAD    pThr = NULL;

    NTSTATUS status = ObReferenceObjectByHandle(
        thread,
        GENERIC_READ,
        *PsThreadType,
        KernelMode,
        (PVOID*)&pThr,
        NULL);
    if (STATUS_SUCCESS == status && NULL != pThr) {
        HANDLE proc = PsGetThreadProcessId(pThr);
        ObDereferenceObject(pThr);
        return proc;
    }
    if (NULL != pThr) {
        ObDereferenceObject(pThr);
    }
    return 0;
}

ULONG GetProcessIdByThreadHandle(HANDLE thread)
{
    PETHREAD    pThr = NULL;

    NTSTATUS status = ObReferenceObjectByHandle(
        thread,
        GENERIC_READ,
        *PsThreadType,
        KernelMode,
        (PVOID*)&pThr,
        NULL);
    if (STATUS_SUCCESS == status && NULL != pThr) {
        HANDLE proc = PsGetThreadProcessId(pThr);
        ObDereferenceObject(pThr);
        return (ULONG)((LONGLONG)proc & 0xffffffff);
    }
    if (NULL != pThr) {
        ObDereferenceObject(pThr);
    }
    return 0;
}

BOOLEAN IsCurrentProcessTarget(HANDLE ProcessHandle)
{
    HANDLE CurrentPsHandle = PsGetProcessId(PsGetCurrentProcess());
    ULONG callerPid = ULONG((LONGLONG)CurrentPsHandle & 0xffffffff);
    ULONG targetPid = GetProcessIdByHandle(ProcessHandle);
    if (targetPid != 0 && callerPid == targetPid) {
        return TRUE;
    }
    return FALSE;
}

BOOLEAN IsCurrentProcessTargetByThread(HANDLE ThreadHandle)
{
    HANDLE CurrentPsHandle = PsGetProcessId(PsGetCurrentProcess());
    ULONG callerPid = ULONG((LONGLONG)CurrentPsHandle & 0xffffffff);
    ULONG targetPid = GetProcessIdByThreadHandle(ThreadHandle);
    if (targetPid != 0 && callerPid == targetPid) {
        return TRUE;
    }
    return FALSE;
}

BOOLEAN GetActionPids(HANDLE ProcessHandle, ULONG* pCallerPid, ULONG* pTargetPid)
{
    HANDLE CurrentPsHandle = PsGetProcessId(PsGetCurrentProcess());
    *pCallerPid = ULONG((LONGLONG)CurrentPsHandle & 0xffffffff);
    *pTargetPid = GetProcessIdByHandle(ProcessHandle);

    return TRUE;
}

BOOLEAN GetActionPidsByThread(HANDLE ThreadHandle, ULONG* pCallerPid, ULONG* pTargetPid)
{
    HANDLE CurrentPsHandle = PsGetProcessId(PsGetCurrentProcess());
    *pCallerPid = ULONG((LONGLONG)CurrentPsHandle & 0xffffffff);
    *pTargetPid = GetProcessIdByThreadHandle(ThreadHandle);

    return TRUE;
}

ULONG IsKnownAPIOffset(PCHAR pAddr)
{
    if (pAddr == (PCHAR)kernel32Base + GLOBALGETATOMA_OFFSET
        || pAddr == (PCHAR)kernel32Base + GLOBALGETATOMW_OFFSET) {
        kprintf("FalconEye: IsKnownAPIOffset: Addr %p matched GlobalGetAtom\n",
            pAddr);
        return eGlobalGetAtom;
    }
    else if (pAddr == (PCHAR)kernel32Base + GLOBALADDATOMA_OFFSET
        || pAddr == (PCHAR)kernel32Base + GLOBALADDATOMW_OFFSET
        || pAddr == (PCHAR)kernel32Base + GLOBALADDATOMEXA_OFFSET
        || pAddr == (PCHAR)kernel32Base + GLOBALADDATOMEXW_OFFSET) {
        kprintf("FalconEye: IsKnownAPIOffset: Addr %p matched GlobalAddAtom\n",
            pAddr);
        return eGlobalAddAtom;
    }
    else if (pAddr == (PCHAR)kernel32Base + LOADLIBA_OFFSET
        || pAddr == (PCHAR)kernel32Base + LOADLIBW_OFFSET
        || pAddr == (PCHAR)kernel32Base + LOADLIBEXA_OFFSET
        || pAddr == (PCHAR)kernel32Base + LOADLIBEXW_OFFSET) {
        kprintf("FalconEye: IsKnownAPIOffset: Addr %p matched LoadLibrary\n",
            pAddr);
        return eLoadLibrary;
    }
    return eUnknownApi;
}