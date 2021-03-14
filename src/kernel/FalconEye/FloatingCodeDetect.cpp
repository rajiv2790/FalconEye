#include "stdafx.h"
#include "NtDefs.h"
#include "entry.h"

BOOLEAN CheckMemImageByAddress(PVOID ptr)
{
    NTSTATUS status = STATUS_SUCCESS;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    SIZE_T  retSize = 0;
    if (NULL == ptr) {
        return FALSE;
    }
    kprintf("[FalconEye] : CheckMemImage for %p.\n", ptr);
    status = ZwQueryVirtualMemory(
        ZwCurrentProcess(),
        ptr, 
        MemoryBasicInformation, 
        &mbi,
        sizeof(MEMORY_BASIC_INFORMATION),
        &retSize);
    if (STATUS_SUCCESS != status) {
        kprintf("[-] : Failed to get MemoryBasicInfo: %p.\n", ptr);
        return FALSE;
    }
    if (!(mbi.Protect & PAGE_EXECUTE)) {
        kprintf("[-] : PAGE at %p is not executable.\n", ptr);
        return FALSE;
    }
    if (!(mbi.Type & MEM_IMAGE)) {
        kprintf("[-] : PAGE at %p is NOT part of IMAGE.\n", ptr);
        return TRUE;
    }
    return FALSE;
}

VOID TestMemImageByAddress()
{
    // non executable address
    CHAR a;
    BOOLEAN bRet = FALSE;
    bRet = CheckMemImageByAddress(&a);
    kprintf("[-] : CheckMemImage returned %d.\n", bRet);

    // executable address
    bRet = CheckMemImageByAddress(TestMemImageByAddress);
    kprintf("[-] : CheckMemImage returned %d.\n", bRet);
}