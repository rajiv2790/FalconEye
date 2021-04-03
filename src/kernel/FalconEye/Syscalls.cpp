#include "stdafx.h"
#include "entry.h"
#include "Syscalls.h"
#include "NtDefs.h"
#include "Helper.h"
#include "ActionHistory.h"
#include "FloatingCodeDetect.h"

PVOID64 NtBaseAddress = NULL;
// offsets
#define NtAddAtomEx_Offset              0x6cf2f0
#define NtWriteVirtualMemory_Offset     0x6de8d0 
//#define NtWriteVirtualMemory_Offset     0x6d5d00 
#define NtSuspendThread_Offset          0x6e4370
#define NtMapViewOfSection_Offset       0x608190
#define NtUnmapViewOfSection_Offset     0x64c2f0
#define NtCreateThread_Offset           0x8c4670
#define NtResumeThread_Offset           0x6cdc70
#define NtQueueApcThread_Offset         0x6d8810
#define NtSetContextThread_Offset       0x8c9de0
#define NtSuspendProcess_Offset         0x8cb0a0
#define NtSetInformationProcess_Offset  0x674ed0
#define NtConnectPort_Offset            0x6cc930
#define NtFlushInstructionCache_Offset  0x6e8fe0
#define NtQueryInformationProcess_Offset    0x5d12e0

// syscall strings 
DEF_USTR_SYSCALL(NtAddAtomEx);
DEF_USTR_SYSCALL(NtWriteVirtualMemory);
DEF_USTR_SYSCALL(NtSuspendThread);
DEF_USTR_SYSCALL(NtMapViewOfSection);
DEF_USTR_SYSCALL(NtUnmapViewOfSection);
DEF_USTR_SYSCALL(NtCreateThread);
DEF_USTR_SYSCALL(NtResumeThread);
DEF_USTR_SYSCALL(NtQueueApcThread);
DEF_USTR_SYSCALL(NtSetContextThread);
DEF_USTR_SYSCALL(NtSuspendProcess);
DEF_USTR_SYSCALL(NtSetInformationProcess);
DEF_USTR_SYSCALL(NtConnectPort);
DEF_USTR_SYSCALL(NtFlushInstructionCache);
DEF_USTR_SYSCALL(NtQueryInformationProcess);

DEF_USTR_SYSCALL(NtUserSetProp);
DEF_USTR_SYSCALL(NtUserSetWindowsHookEx);
DEF_USTR_SYSCALL(NtUserSetWindowLongPtr);
DEF_USTR_SYSCALL(NtUserPostMessage);
DEF_USTR_SYSCALL(NtUserMessageCall);
DEF_USTR_SYSCALL(NtUserPostThreadMessage);
DEF_USTR_SYSCALL(NtUserSendInput);

// original syscall ptrs
DEF_ORIG_SYSCALL_PTR(NtAddAtomEx);
DEF_ORIG_SYSCALL_PTR(NtWriteVirtualMemory);
DEF_ORIG_SYSCALL_PTR(NtSuspendThread);
DEF_ORIG_SYSCALL_PTR(NtMapViewOfSection);
DEF_ORIG_SYSCALL_PTR(NtUnmapViewOfSection);
DEF_ORIG_SYSCALL_PTR(NtCreateThread);
DEF_ORIG_SYSCALL_PTR(NtResumeThread);
DEF_ORIG_SYSCALL_PTR(NtQueueApcThread);
DEF_ORIG_SYSCALL_PTR(NtSetContextThread);
DEF_ORIG_SYSCALL_PTR(NtSuspendProcess);
DEF_ORIG_SYSCALL_PTR(NtSetInformationProcess);
DEF_ORIG_SYSCALL_PTR(NtConnectPort);
DEF_ORIG_SYSCALL_PTR(NtFlushInstructionCache);
DEF_ORIG_SYSCALL_PTR(NtQueryInformationProcess);

DEF_ORIG_SYSCALL_PTR(NtUserSetProp);
DEF_ORIG_SYSCALL_PTR(NtUserSetWindowsHookEx);
DEF_ORIG_SYSCALL_PTR(NtUserSetWindowLongPtr);
DEF_ORIG_SYSCALL_PTR(NtUserPostMessage);
DEF_ORIG_SYSCALL_PTR(NtUserMessageCall);
DEF_ORIG_SYSCALL_PTR(NtUserPostThreadMessage);
DEF_ORIG_SYSCALL_PTR(NtUserSendInput);

NTSTATUS GetSyscallAddresses()
{
    NTSTATUS     status = STATUS_SUCCESS;

    ADD_SYSCALL_ADDR(NtAddAtomEx);
    ADD_SYSCALL_ADDR(NtWriteVirtualMemory);
    ADD_SYSCALL_ADDR(NtSuspendThread);
    ADD_SYSCALL_ADDR(NtMapViewOfSection);
    ADD_SYSCALL_ADDR(NtUnmapViewOfSection);
    ADD_SYSCALL_ADDR(NtCreateThread);
    ADD_SYSCALL_ADDR(NtResumeThread);
    ADD_SYSCALL_ADDR(NtQueueApcThread);
    ADD_SYSCALL_ADDR(NtSetContextThread);
    ADD_SYSCALL_ADDR(NtSuspendProcess);
    ADD_SYSCALL_ADDR(NtSetInformationProcess);
    ADD_SYSCALL_ADDR(NtConnectPort);
    ADD_SYSCALL_ADDR(NtFlushInstructionCache);
    ADD_SYSCALL_ADDR(NtQueryInformationProcess);
#if 0
    ADD_SYSCALL_ADDR(NtUserSetProp);
    ADD_SYSCALL_ADDR(NtUserSetWindowsHookEx);
#endif
    return status;
}

PVOID64 FindNtBase(PVOID64 start)
{
    UCHAR* It = (UCHAR*)start;
    PVOID64 NtBase =  NULL;
    // Find ntoskrnl base
    while (true) {
        It = (UCHAR*)(ULONG64(It - 1) & ~0xFFF);
        if (PIMAGE_DOS_HEADER(It)->e_magic == IMAGE_DOS_SIGNATURE) {
            NtBase = It;
            break;
        }
    }
    if (NtBase) {
        kprintf("FalconEye: NtBase: %p.\n", NtBase);
    }
    NtBaseAddress = NtBase;
    return NtBase;
}

NTSTATUS DetourNtAddAtomEx(
    _In_reads_bytes_opt_(Length) PWSTR AtomName,
    _In_ ULONG Length,
    _Out_opt_ PRTL_ATOM Atom,
    _In_ ULONG Flags
    )
{
    //kprintf("FalconEye: DetourNtAddAtomEx: AtomName %S.\n", AtomName);
    return NtAddAtomExOrigPtr(AtomName, Length, Atom, Flags);
}

NTSTATUS DetourNtWriteVirtualMemory(
    _In_ HANDLE               ProcessHandle,
    _In_ PVOID                BaseAddress,
    _In_ PVOID                Buffer,
    _In_ ULONG                NumberOfBytesToWrite,
    _Out_opt_ PULONG          NumberOfBytesWritten)
{
    if (SELF_PROCESS_HANDLE != ProcessHandle) {
        //TestMemImageByAddress(Buffer);
        ULONG callerPid, targetPid;
        GetActionPids(ProcessHandle, &callerPid, &targetPid);
        AddNtWriteVirtualMemoryEntry(callerPid, targetPid, BaseAddress, Buffer, NumberOfBytesToWrite);
    }
    return NtWriteVirtualMemoryOrigPtr(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS DetourNtSuspendThread(
    _In_ HANDLE               ThreadHandle,
    _Out_opt_ PULONG          PreviousSuspendCount)
{
    if (SELF_PROCESS_HANDLE != ThreadHandle) {
        ULONG callerPid, targetPid;
        GetActionPidsByThread(ThreadHandle, &callerPid, &targetPid);
        if (callerPid != targetPid) {
            ULONG targetTid = GetThreadIdByHandle(ThreadHandle);
            kprintf("FalconEye: DetourNtSuspendThread: callerPid %d targetPid %d targetTid %d.\n", callerPid, targetPid, targetTid);
            AddNtSuspendThreadEntry(callerPid, targetPid, targetTid);
        }
    }
    
    return NtSuspendThreadOrigPtr(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS DetourNtMapViewOfSection(
    _In_ HANDLE               SectionHandle,
    _In_ HANDLE               ProcessHandle,
    _In_ PVOID*               BaseAddress,
    _In_ ULONG                ZeroBits,
    _In_ ULONG                CommitSize,
    _In_ PLARGE_INTEGER       SectionOffset,
    _In_ PULONG               ViewSize,
    _In_ SECTION_INHERIT	  InheritDisposition,
    _In_ ULONG                AllocationType,
    _In_ ULONG                Protect)
{
    if (SELF_PROCESS_HANDLE != ProcessHandle) {
        ULONG callerPid = 0, targetPid = 0;
        //GetActionPids(ProcessHandle, &callerPid, &targetPid);
        kprintf("FalconEye: DetourNtMapViewOfSection: SectionHandle %p CallerPid %d TargetPid %d BaseAddress %p Commitsize %d.\n", 
            SectionHandle, callerPid, targetPid, BaseAddress, CommitSize);
    }
    return NtMapViewOfSectionOrigPtr(SectionHandle, ProcessHandle, BaseAddress, 
        ZeroBits, CommitSize, SectionOffset, 
        ViewSize, InheritDisposition, AllocationType, Protect);
}

NTSTATUS DetourNtUnmapViewOfSection(
    _In_ HANDLE               ProcessHandle,
    _In_ PVOID                BaseAddress)
{
    if (SELF_PROCESS_HANDLE != ProcessHandle) {
        ULONG callerPid, targetPid;
        GetActionPids(ProcessHandle, &callerPid, &targetPid);
        kprintf("FalconEye: DetourNtUnmapViewOfSection: CallerPid %d TargetPid %d BaseAddress %p.\n",
            callerPid, targetPid, BaseAddress);
        AddNtUnmapViewOfSectionEntry(callerPid, targetPid, BaseAddress);
    }
    //kprintf("FalconEye: DetourNtUnmapViewOfSection: ProcessHandle %p.\n", ProcessHandle);
    return NtUnmapViewOfSectionOrigPtr(ProcessHandle, BaseAddress);
}

NTSTATUS DetourNtCreateThread(
    _Out_ PHANDLE             ThreadHandle,
    _In_ ACCESS_MASK          DesiredAccess,
    _In_ POBJECT_ATTRIBUTES   ObjectAttributes,
    _In_ HANDLE               ProcessHandle,
    _Out_ PCLIENT_ID          ClientId,
    _In_ PCONTEXT             ThreadContext,
    _In_ PINITIAL_TEB         InitialTeb,
    _In_ BOOLEAN              CreateSuspended)
{
    if (SELF_PROCESS_HANDLE != ProcessHandle) {
        ULONG callerPid, targetPid;
        GetActionPids(ProcessHandle, &callerPid, &targetPid);
        kprintf("FalconEye: DetourNtCreateThread: CallerPid %d TargetPid %d.\n",
            callerPid, targetPid);
    }
    //kprintf("FalconEye: DetourNtCreateThread: ProcessHandle %p.\n", ProcessHandle);
    return NtCreateThreadOrigPtr(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

NTSTATUS DetourNtResumeThread(
    _In_ HANDLE             ThreadHandle,
    _Out_opt_ PULONG        SuspendCount)
{
    if (SELF_PROCESS_HANDLE != ThreadHandle) {
        ULONG callerPid, targetPid;
        GetActionPidsByThread(ThreadHandle, &callerPid, &targetPid);
        if (callerPid != targetPid) {
            ULONG targetTid = GetThreadIdByHandle(ThreadHandle);
            kprintf("FalconEye: DetourNtResumeThread: callerPid %d targetPid %d targetTid %d.\n",
                callerPid, targetPid, targetTid);
        }
    }
    return NtResumeThreadOrigPtr(ThreadHandle, SuspendCount);
}

NTSTATUS DetourNtQueueApcThread(
    _In_ HANDLE               ThreadHandle,
    _In_ PIO_APC_ROUTINE      ApcRoutine,
    _In_ PVOID                ApcRoutineContext,
    _In_ PIO_STATUS_BLOCK     ApcStatusBlock,
    _In_ ULONG                ApcReserved)
{
    
    if (SELF_PROCESS_HANDLE != ThreadHandle) {
        ULONG callerPid, targetPid;

        GetActionPidsByThread(ThreadHandle, &callerPid, &targetPid);
        
        if (callerPid != targetPid) {
            kprintf("FalconEye*****************************: DetourNtQueueApcThread: callerPID %llu targetPID %llu ApcRoutine %p\n", callerPid, targetPid, ApcRoutine);
            
            //ULONG targetTid = GetThreadIdByHandle(ThreadHandle);
            //UNREFERENCED_PARAMETER(targetTid);
            /*kprintf("FalconEye: DetourNtQueueApcThread: callerPid %d targetPid %d ApcRoutine %p ApcContext %p.\n",
                callerPid, targetPid, ApcRoutine, ApcRoutineContext);*/ 
        }
        
    }
    
    return NtQueueApcThreadOrigPtr(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
}

NTSTATUS DetourNtSetContextThread(
    _In_ HANDLE               ThreadHandle,
    _In_ PCONTEXT             Context)
{
    if (SELF_PROCESS_HANDLE != ThreadHandle) {
        ULONG callerPid, targetPid;
        GetActionPidsByThread(ThreadHandle, &callerPid, &targetPid);
        if (callerPid != targetPid) {
            ULONG targetTid = GetThreadIdByHandle(ThreadHandle);
            kprintf("FalconEye: DetourNtSetContextThread: callerPid %d targetPid %d targetTid %d Context %p.\n",
                callerPid, targetPid, targetTid, Context);
        }
    }
    return NtSetContextThreadOrigPtr(ThreadHandle, Context);
}

NTSTATUS DetourNtSuspendProcess(
    _In_ HANDLE ProcessHandle)
{
    if (SELF_PROCESS_HANDLE != ProcessHandle) {
        ULONG callerPid, targetPid;
        GetActionPids(ProcessHandle, &callerPid, &targetPid);
        kprintf("FalconEye: DetourNtSuspendProcess: callerPid %d targetPid %d.\n",
            callerPid, targetPid);
    }
    return NtSuspendProcessOrigPtr(ProcessHandle);
}

NTSTATUS DetourNtSetInformationProcess(
    _In_ HANDLE               ProcessHandle,
    _In_ PROCESSINFOCLASS	  ProcessInformationClass,
    _In_ PVOID                ProcessInformation,
    _In_ ULONG                ProcessInformationLength)
{
    if (SELF_PROCESS_HANDLE != ProcessHandle) {
        ULONG callerPid, targetPid;
        GetActionPids(ProcessHandle, &callerPid, &targetPid);
        /*
        kprintf("FalconEye: DetourNtSetInformationProcess: callerPid %d targetPid %d InfoClass %d.\n",
            callerPid, targetPid, ProcessInformationClass);
        */
    }
    return NtSetInformationProcessOrigPtr(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS DetourNtConnectPort(
    _Out_ PHANDLE             ClientPortHandle,
    _In_ PUNICODE_STRING      ServerPortName,
    _In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    _In_ _Out_opt_ PLPC_SECTION_OWNER_MEMORY ClientSharedMemory,
    _Out_opt_ PLPC_SECTION_MEMORY ServerSharedMemory,
    _Out_opt_ PULONG              MaximumMessageLength,
    _In_ PVOID                ConnectionInfo,
    _In_ PULONG               ConnectionInfoLength)
{
    HANDLE CurrentPsHandle = PsGetProcessId(PsGetCurrentProcess());
    ULONG callerPid = ULONG((LONGLONG)CurrentPsHandle & 0xffffffff);
    if (NULL != ServerPortName) {
        kprintf("FalconEye: DetourNtConnectPort: callerPid %d serverPort %wZ connectionInfo %p.\n",
            callerPid, ServerPortName, ConnectionInfo);
    }
    return NtConnectPortOrigPtr(ClientPortHandle, ServerPortName, SecurityQos, ClientSharedMemory, ServerSharedMemory, MaximumMessageLength, ConnectionInfo, ConnectionInfoLength);
}

NTSTATUS DetourNtFlushInstructionCache(
    _In_ HANDLE               ProcessHandle,
    _In_ PVOID                BaseAddress,
    _In_ ULONG                NumberOfBytesToFlush)
{
    if (SELF_PROCESS_HANDLE != ProcessHandle) {
        ULONG callerPid, targetPid;
        GetActionPids(ProcessHandle, &callerPid, &targetPid);
        kprintf("FalconEye: DetourNtFlushInstructionCache: callerPid %d targetPid %d BaseAddress %p BytesToFlush %d.\n",
            callerPid, targetPid, BaseAddress, NumberOfBytesToFlush);
    }
    return NtFlushInstructionCacheOrigPtr(ProcessHandle, BaseAddress, NumberOfBytesToFlush);
}

NTSTATUS DetourNtQueryInformationProcess(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    )
{
    if (SELF_PROCESS_HANDLE != ProcessHandle) {
        ULONG callerPid, targetPid;
        GetActionPids(ProcessHandle, &callerPid, &targetPid);
        // kprintf("FalconEye: DetourNtQueryInformationProcess: callerPid %d targetPid %d InfoClass %d.\n",
        //    callerPid, targetPid, ProcessInformationClass);
    }
    return NtQueryInformationProcessOrigPtr(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

BOOL DetourNtUserSetProp(
    _In_ HWND hWnd,
    _In_ ATOM Atom,
    _In_ HANDLE Data)
{
    kprintf("FalconEye: DetourNtUserSetProp: hWnd %p.\n", hWnd);
    return NtUserSetPropOrigPtr(hWnd, Atom, Data);
}


void SaveOriginalFunctionAddress(
    unsigned int SystemCallIndex,
    void** SystemCallFunction)
{
    SAVE_FN_ADDR(0x3A, NtWriteVirtualMemory);
    SAVE_FN_ADDR(0x45, NtQueueApcThread);
    SAVE_FN_ADDR(0x19, NtQueryInformationProcess);
    SAVE_FN_ADDR(0x1c, NtSetInformationProcess);
    SAVE_FN_ADDR(0x28, NtMapViewOfSection);
    SAVE_FN_ADDR(0x2a, NtUnmapViewOfSection);
    SAVE_FN_ADDR(0x52, NtResumeThread);
    SAVE_FN_ADDR(0x9e, NtConnectPort);
    SAVE_FN_ADDR(0x1b6, NtSuspendThread);
    SAVE_FN_ADDR(0x185, NtSetContextThread);
    SAVE_FN_ADDR(0x1b5, NtSuspendProcess);
    SAVE_FN_ADDR(0xe2, NtFlushInstructionCache);
    SAVE_FN_ADDR(0x4e, NtCreateThread);

#if 0
    if (0x104C == SystemCallIndex) {
        kprintf("[+] FalconEye: NtUserSetProp %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
        if (NULL == NtUserSetPropOrigPtr) {
            NtUserSetPropOrigPtr = (NtUserSetProp_t)*SystemCallFunction;
        }
    }
    if (0x1089 == SystemCallIndex) {
        kprintf("[+] FalconEye: NtUserSetWindowsHookEx %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
        if (NULL == NtUserSetWindowsHookExOrigPtr) {
            NtUserSetWindowsHookExOrigPtr = (NtUserSetWindowsHookEx_t)*SystemCallFunction;
        }
    }
    if (0x1523 == SystemCallIndex) {
        kprintf("[+] FalconEye: NtUserSetWindowLongPtr %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
        if (NULL == NtUserSetWindowLongPtrOrigPtr) {
            NtUserSetWindowLongPtrOrigPtr = (NtUserSetWindowLongPtr_t)*SystemCallFunction;
        }
    }
    if (0x100F == SystemCallIndex) {
        kprintf("[+] FalconEye: NtUserPostMessage %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
        if (NULL == NtUserPostMessageOrigPtr) {
            NtUserPostMessageOrigPtr = (NtUserPostMessage_t)*SystemCallFunction;
        }
    }
    if (0x1007 == SystemCallIndex) {
        kprintf("[+] FalconEye: NtUserMessageCall %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
        if (NULL == NtUserMessageCallOrigPtr) {
            NtUserMessageCallOrigPtr = (NtUserMessageCall_t)*SystemCallFunction;
        }
    }
    if (0x105E == SystemCallIndex) {
        kprintf("[+] FalconEye: NtUserPostThreadMessage %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
        if (NULL == NtUserPostThreadMessageOrigPtr) {
            NtUserPostThreadMessageOrigPtr = (NtUserPostThreadMessage_t)*SystemCallFunction;
        }
    }
    if (0x107F == SystemCallIndex) {
        kprintf("[+] FalconEye: NtUserSendInput %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
        if (NULL == NtUserSendInputOrigPtr) {
            NtUserSendInputOrigPtr = (NtUserSendInput_t)*SystemCallFunction;
        }
    }
#endif
}

PVOID GetDetourFunction(unsigned int idx)
{
    switch (idx) {
    case 0x3A:
        return DetourNtWriteVirtualMemory;
    case 0x45:
        return DetourNtQueueApcThread;
    case 0x19: 
        return DetourNtQueryInformationProcess;
    case 0x1c: 
        return DetourNtSetInformationProcess;
    //case 0x28: 
        //return DetourNtMapViewOfSection;
    //case 0x2a: 
        //return DetourNtUnmapViewOfSection;
    case 0x52: 
        return DetourNtResumeThread;
    case 0x9e: 
        return DetourNtConnectPort;
    case 0x1b6:
        return DetourNtSuspendThread;
    case 0x185:
        return DetourNtSetContextThread;
    case 0x1b5:
        return DetourNtSuspendProcess;
    case 0xe2:
        return DetourNtFlushInstructionCache;
    case 0x4e:
        return DetourNtCreateThread;
    default:
        return NULL;
    }
}