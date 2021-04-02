#include "stdafx.h"
#include "NtDefs.h"
#include "entry.h"

BOOLEAN CheckMemImageByAddress(PVOID ptr, HANDLE pHandle)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE PHANDLE;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    SIZE_T  retSize = 0;
    if (NULL == ptr) {
        return FALSE;
    }
    if (NULL == pHandle)
    {
        PHANDLE = ZwCurrentProcess();
    }
    else
    {
        PHANDLE = pHandle;
    }
    //kprintf("[FalconEye] : CheckMemImage for %p.\n", ptr);
    status = ZwQueryVirtualMemory(
        PHANDLE,
        ptr, 
        MemoryBasicInformation, 
        &mbi,
        sizeof(MEMORY_BASIC_INFORMATION),
        &retSize);
    if (STATUS_SUCCESS != status) {
        kprintf("[-] : Failed to get MemoryBasicInfo: %p. Status %x\n", ptr, status);
        return FALSE;
    }
    /*
    if (!(mbi.Protect & PAGE_EXECUTE)) {
        kprintf("[-] : PAGE at %p is not executable. Mem Protection is %p\n", ptr, mbi.Protect);
        return FALSE;
    }
    */
    if (!(mbi.Type & MEM_IMAGE)) {
        //kprintf("[-] : PAGE at %p is NOT part of IMAGE.\n", ptr);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN bTested = FALSE;
VOID TestMemImageByAddress(PVOID addr)
{
    // non executable address
    if (!bTested) {
        BOOLEAN bRet = FALSE;
        bRet = CheckMemImageByAddress(addr, NULL);
        kprintf("[-] : CheckMemImage returned %d.\n", bRet);
        bTested = TRUE;
    }
}