#include "stdafx.h"
#include "Helper.h"

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
    ObDereferenceObject(pProc);
    return 0;
}