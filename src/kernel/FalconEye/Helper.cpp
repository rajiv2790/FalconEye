#include "stdafx.h"
#include "Helper.h"
#include "NtDefs.h"

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
        alertf("FalconEye: IsKnownAPIOffset: Addr %p matched GlobalGetAtom\n",
            pAddr);
        return eGlobalGetAtom;
    }
    else if (pAddr == (PCHAR)kernel32Base + GLOBALADDATOMA_OFFSET
        || pAddr == (PCHAR)kernel32Base + GLOBALADDATOMW_OFFSET
        || pAddr == (PCHAR)kernel32Base + GLOBALADDATOMEXA_OFFSET
        || pAddr == (PCHAR)kernel32Base + GLOBALADDATOMEXW_OFFSET) {
        alertf("FalconEye: IsKnownAPIOffset: Addr %p matched GlobalAddAtom\n",
            pAddr);
        return eGlobalAddAtom;
    }
    else if (pAddr == (PCHAR)kernel32Base + LOADLIBA_OFFSET
        || pAddr == (PCHAR)kernel32Base + LOADLIBW_OFFSET
        || pAddr == (PCHAR)kernel32Base + LOADLIBEXA_OFFSET
        || pAddr == (PCHAR)kernel32Base + LOADLIBEXW_OFFSET) {
        alertf("FalconEye: IsKnownAPIOffset: Addr %p matched LoadLibrary\n",
            pAddr);
        return eLoadLibrary;
    }
    else if (pAddr == (PCHAR)kernel32Base + GETPROC_OFFSET) {
        alertf("FalconEye: IsKnownAPIOffset: Addr %p matched GetProcAddress\n",
            pAddr);
        return eGetProcAddr;
    }
    else if (pAddr == (PCHAR)ntdllBase + MEMSET_OFFSET) {
        alertf("FalconEye: IsKnownAPIOffset: Addr %p matched memset\n",
            pAddr);
        return eMemsetAddr;
    }
    else if (pAddr == (PCHAR)kernel32Base + SETTHREADCTX_OFFSET) {
        alertf("FalconEye: IsKnownAPIOffset: Addr %p matched SetThreadContext\n",
            pAddr);
        return eSetThreadCtx;
    }
    return eUnknownApi;
}

BOOLEAN IsAddressInKernelBase(PCHAR pAddr)
{
    if (kernelbaseBase != NULL && kernelbaseEnd != NULL)
    {
        if ((pAddr >= (PCHAR)kernelbaseBase) && (pAddr <= (PCHAR)kernelbaseEnd))
        {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN IsAddressKCT(PCHAR pAddr, HANDLE pid)
{
    PEPROCESS pEproc = NULL;
    PPEB peb = NULL;
    ULONG64 kct = 0;
    PCHAR kctOffset = NULL;

    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &pEproc);
    if (!NT_SUCCESS(status)) {
        kprintf("PsLookupProcessByProcessId failed %x", status);
    }
    if (pEproc)
    {
        peb = PsGetProcessPeb(pEproc);
        kct = FIELD_OFFSET(PEB, KernelCallbackTable);
        kctOffset = (PCHAR)peb + kct;

        if (kctOffset == pAddr)
        {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN IsValidPEHeader(CHAR* buffer, size_t size)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)buffer;
    if (IMAGE_DOS_SIGNATURE == idh->e_magic) {
        return true;
    }
    else if (0 != idh->e_lfanew && idh->e_lfanew < size) {
        IMAGE_NT_HEADERS* inh =
            (IMAGE_NT_HEADERS*)((CHAR*)buffer + idh->e_lfanew);
        if (inh->Signature == IMAGE_NT_SIGNATURE) {
            return TRUE;
        }
    }
    
    return FALSE;
}

BOOLEAN IsDrivePresent(char c)
{
    LONG offset = -1;
    if (c >= 'A' && c <= 'Z') {
        offset = c - 'A';
    }
    else {
        offset = c - 'a';
    }
    if (offset >= 2) {
        return TRUE;
    }
    return FALSE;
}

BOOLEAN isallowedchar(char c)
{
    if ('.' == c || '\\' == c || '/' == c || ':' == c || '.' == c) {
        return TRUE;
    }
    return FALSE;
}

BOOLEAN isalphanum(char c)
{
    if ((c >= 'A' && c <= 'Z') 
        || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9')
        ){
        return TRUE;
    }    
    return FALSE;
}

BOOLEAN GetAsciiPathFromBuffer(CHAR* buffer, size_t offset, size_t size)
{
    CHAR path[MAX_PATH] = { 0 };
    auto j = 0;
    for (auto i = offset; i < min(size, offset + MAX_PATH); i++) {
        if (isalphanum(buffer[i]) || isallowedchar(buffer[i])) {
            path[j++] = buffer[i];
        }
        else {
            break;
        }
    }
    alertf("\n[+] FalconEye: **************************Alert**************************\n"
        "DLL path at offset %d : %s", offset, path);
    alertf("\n");
    return TRUE;
}

BOOLEAN GetWcharPathFromBuffer(CHAR* buffer, size_t offset, size_t size)
{
    WCHAR path[MAX_PATH] = { 0 };
    auto j = 0;
    for (auto i = offset; i < min(size, offset + MAX_PATH * sizeof(wchar_t)); i += 2) {
        if (isalphanum(buffer[i]) || isallowedchar(buffer[i])) {
            path[j++] = buffer[i];
        }
        else {
            break;
        }
    }
    alertf("\n[+] FalconEye: **************************Alert**************************\n"
        "DLL path at offset %d : %S", offset, path);
    alertf("\n");
    return TRUE;
}

BOOLEAN IsValidDllPath(CHAR* buffer, size_t size)
{
    ULONG offsets[] = { 0, 8, 16 };
    if (size < MAX_DLL_START_OFFSET) {
        return FALSE;
    }
    for (auto i = 0; i < sizeof(offsets) / sizeof(ULONG); i++) {
        // ascii check
        if (buffer[offsets[i] + 1] == ':' && buffer[offsets[i] + 2] == '\\') {
            if (IsDrivePresent(buffer[offsets[i]])) {
                kprintf("[+] falconeye: Possible ASCII path found at offset %d ", offsets[i]);
                GetAsciiPathFromBuffer(buffer, offsets[i], size);
                return TRUE;
            }
        } // wide char check
        else if (buffer[offsets[i] + 2] == ':' && buffer[offsets[i] + 4] == '\\') {
            if (IsDrivePresent(buffer[offsets[i]])) {
                kprintf("[+] falconeye: Possible WCHAR path found at offset %d", offsets[i]);
                GetWcharPathFromBuffer(buffer, offsets[i], size);
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOLEAN GetVolumeDeviceForSymLink(PUNICODE_STRING volumeLetter, PUNICODE_STRING target)
{
    HANDLE  link;
    OBJECT_ATTRIBUTES   objAttrs;

    InitializeObjectAttributes(
        &objAttrs,
        volumeLetter,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );
    NTSTATUS status = ZwOpenSymbolicLinkObject(
        &link, GENERIC_READ, &objAttrs);
    if (STATUS_SUCCESS == status) {
        ULONG len = 0;
        status = ZwQuerySymbolicLinkObject(link, target, &len);
        if (STATUS_SUCCESS == status) {
            kprintf("[+] falconeye: For path %wZ\n", target);
            ZwClose(link);
            return TRUE;
        }
        ZwClose(link);
    }
    return FALSE;
}

VolDeviceEntry  VolDeviceMap[MAX_VOL_DEVICE_ENTRIES];
ULONG           volDeviceIdx = 0;
BOOLEAN GetVolumeList()
{
    WCHAR volumeLetter[10] = L"\\??\\C:";
    for (auto i = L'C'; i <= L'Z'; i++) {
        UNICODE_STRING  volume;
        volumeLetter[4] = i;
        RtlInitUnicodeString(&volume, volumeLetter);
        UNICODE_STRING target = { 0 };
        WCHAR wcTarget[MAX_PATH] = { 0 };
        RtlInitUnicodeString(&target, wcTarget);
        target.MaximumLength = MAX_PATH;
        if (FALSE == GetVolumeDeviceForSymLink(&volume, &target)) {
            break;
        }
        kprintf("[+] falconeye: Adding VolDevMap entry %S : %wZ\n", volumeLetter, target);
        if (MAX_DEVICE_LEN > target.Length/sizeof(WCHAR) && volDeviceIdx < MAX_VOL_DEVICE_ENTRIES) {
            VolDeviceMap[volDeviceIdx].volumeLetter = i;
            RtlCopyMemory(VolDeviceMap[volDeviceIdx].device, target.Buffer, target.Length);
            volDeviceIdx++;
        }
    }
    return TRUE;
}

BOOLEAN GetDeviceForVolume(WCHAR volume, PWCHAR device)
{
    for (ULONG i = 0; i <= volDeviceIdx; i++) {
        if (volume == VolDeviceMap[i].volumeLetter) {
            wcscpy (device, VolDeviceMap[i].device);
            kprintf("[+] FalconEye: Found VolDevMap entry %C : %S\n", volume, device);
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN ConvertDosPathToDevicePath(PWCHAR dosPath, PWCHAR devicePath)
{
    if (NULL == dosPath || NULL == devicePath) {
        return FALSE;
    }
    WCHAR devicePrefix[MAX_DEVICE_LEN] = { 0 };
    if (GetDeviceForVolume(dosPath[0], devicePrefix)) {
        wcscpy(devicePath, devicePrefix);
        wcscat(devicePath, &dosPath[2]);
        kprintf("[+] FalconEye: DosPath : %S DevicePath : %S\n", dosPath, devicePath);
        return TRUE;
    }
    return FALSE;
}

/*
* This function tokenizes the full file path
* and compares the filename with the string supplied
*/
LONG compareFilename(
    PUNICODE_STRING  FullImageName,
    UNICODE_STRING str, BOOLEAN bGetLastToken)
{
    LONG ret = 1;
    UNICODE_STRING token, remainingToken;
    //Tokenize the FullImageName and compare the last token
    if (bGetLastToken)
    {
        FsRtlDissectName(*FullImageName, &token, &remainingToken);
        while (token.Length != 0)
        {
            if (remainingToken.Length == 0)
            {
                break;
            }
            FsRtlDissectName(remainingToken, &token, &remainingToken);
        }
        ret = RtlCompareUnicodeString(&token, &str, TRUE);
    }
    //Tokenize the FullImageName and compare to the remaining string
    //First token is discarded
    else
    {
        FsRtlDissectName(*FullImageName, &token, &remainingToken);
        while (token.Length != 0)
        {
            if (remainingToken.Length == 0)
            {
                break;
            }
            if (RtlCompareUnicodeString(&remainingToken, &str, TRUE) == 0)
            {
                ret = 0;
                break;
            }
            FsRtlDissectName(remainingToken, &token, &remainingToken);
        }
    }
    return ret;
}