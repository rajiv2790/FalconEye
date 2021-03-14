#include "stdafx.h"
#include "entry.h"
#include "Syscalls.h"

PVOID64 NtBaseAddress = NULL;
// offsets
#define NtAddAtomEx_Offset              0x6cf2f0
#define NtWriteVirtualMemory_Offset     0x6de8d0
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

// syscall definitions

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
    while (true)
    {
        It = (UCHAR*)(ULONG64(It - 1) & ~0xFFF);
        if (PIMAGE_DOS_HEADER(It)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            NtBase = It;
            break;
        }
    }
    if (NtBase)
    {
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
    kprintf("FalconEye: DetourNtAddAtomEx: AtomName %S.\n", AtomName);
    return NtAddAtomExOrigPtr(AtomName, Length, Atom, Flags);
}

NTSTATUS DetourNtWriteVirtualMemory(
    _In_ HANDLE               ProcessHandle,
    _In_ PVOID                BaseAddress,
    _In_ PVOID                Buffer,
    _In_ ULONG                NumberOfBytesToWrite,
    _Out_opt_ PULONG          NumberOfBytesWritten)
{
    kprintf("FalconEye: DetourNtWriteVirtualMemory: Handle %p Buffer %p.\n", ProcessHandle, Buffer);
    return NtWriteVirtualMemoryOrigPtr(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS DetourNtSuspendThread(
    _In_ HANDLE               ThreadHandle,
    _Out_opt_ PULONG          PreviousSuspendCount)
{
    kprintf("FalconEye: DetourNtSuspendThread: ThreadHandle %p.\n", ThreadHandle);
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
    kprintf("FalconEye: DetourNtMapViewOfSection: SectionOffset %p.\n", SectionOffset);
    return NtMapViewOfSectionOrigPtr(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
}

NTSTATUS DetourNtUnmapViewOfSection(
    _In_ HANDLE               ProcessHandle,
    _In_ PVOID                BaseAddress)
{
    kprintf("FalconEye: DetourNtUnmapViewOfSection: ProcessHandle %p.\n", ProcessHandle);
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
    kprintf("FalconEye: DetourNtCreateThread: ProcessHandle %p.\n", ProcessHandle);
    return NtCreateThreadOrigPtr(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

NTSTATUS DetourNtResumeThread(
    _In_ HANDLE             ThreadHandle,
    _Out_opt_ PULONG        SuspendCount)
{
    kprintf("FalconEye: DetourNtResumeThread: ThreadHandle %p.\n", ThreadHandle);
    return NtResumeThreadOrigPtr(ThreadHandle, SuspendCount);
}

NTSTATUS DetourNtQueueApcThread(
    _In_ HANDLE               ThreadHandle,
    _In_ PIO_APC_ROUTINE      ApcRoutine,
    _In_ PVOID                ApcRoutineContext,
    _In_ PIO_STATUS_BLOCK     ApcStatusBlock,
    _In_ ULONG                ApcReserved)
{
    kprintf("FalconEye: DetourNtQueueApcThread: ThreadHandle %p.\n", ThreadHandle);
    return NtQueueApcThreadOrigPtr(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
}

NTSTATUS DetourNtSetContextThread(
    _In_ HANDLE               ThreadHandle,
    _In_ PCONTEXT             Context)
{
    kprintf("FalconEye: DetourNtSetContextThread: ThreadHandle %p.\n", ThreadHandle);
    return NtSetContextThreadOrigPtr(ThreadHandle, Context);
}

NTSTATUS DetourNtSuspendProcess(
    _In_ HANDLE ProcessHandle)
{
    kprintf("FalconEye: DetourNtSuspendProcess: ProcessHandle %p.\n", ProcessHandle);
    return NtSuspendProcessOrigPtr(ProcessHandle);
}

NTSTATUS DetourNtSetInformationProcess(
    _In_ HANDLE               ProcessHandle,
    _In_ PROCESSINFOCLASS	  ProcessInformationClass,
    _In_ PVOID                ProcessInformation,
    _In_ ULONG                ProcessInformationLength)
{
    kprintf("FalconEye: DetourNtSetInformationProcess: ProcessHandle %p.\n", ProcessHandle);
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
    kprintf("FalconEye: DetourNtConnectPort: ClientPortHandle %p.\n", ClientPortHandle);
    return NtConnectPortOrigPtr(ClientPortHandle, ServerPortName, SecurityQos, ClientSharedMemory, ServerSharedMemory, MaximumMessageLength, ConnectionInfo, ConnectionInfoLength);
}

NTSTATUS DetourNtFlushInstructionCache(
    _In_ HANDLE               ProcessHandle,
    _In_ PVOID                BaseAddress,
    _In_ ULONG                NumberOfBytesToFlush)
{
    kprintf("FalconEye: DetourNtFlushInstructionCache: BaseAddress %p.\n", BaseAddress);
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
    kprintf("FalconEye: DetourNtQueryInformationProcess: ProcessHandle %p.\n", ProcessHandle);
    return NtQueryInformationProcessOrigPtr(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

PVOID UpdateSystemCallFunction(PVOID OrigSyscall)
{
    if (OrigSyscall == NtWriteVirtualMemoryOrigPtr) {
        return DetourNtWriteVirtualMemory;
    }
    else if (OrigSyscall == NtAddAtomExOrigPtr) {
        return DetourNtAddAtomEx;
    }
    else if (OrigSyscall == NtSuspendThreadOrigPtr) {
        return DetourNtSuspendThread;
    }
    else if (OrigSyscall == NtMapViewOfSectionOrigPtr) {
        return DetourNtMapViewOfSection;
    }
    else if (OrigSyscall == NtUnmapViewOfSectionOrigPtr) {
        return DetourNtUnmapViewOfSection;
    }
    else if (OrigSyscall == NtCreateThreadOrigPtr) {
        return DetourNtCreateThread;
    }
    else if (OrigSyscall == NtResumeThreadOrigPtr) {
        return DetourNtResumeThread;
    }
    else if (OrigSyscall == NtQueueApcThreadOrigPtr) {
        return DetourNtQueueApcThread;
    }
    else if (OrigSyscall == NtSetContextThreadOrigPtr) {
        return DetourNtSetContextThread;
    }
    else if (OrigSyscall == NtSuspendProcessOrigPtr) {
        return DetourNtSuspendProcess;
    }
    else if (OrigSyscall == NtSetInformationProcessOrigPtr) {
        return DetourNtSetInformationProcess;
    }
    else if (OrigSyscall == NtConnectPortOrigPtr) {
        return DetourNtConnectPort;
    }
    else if (OrigSyscall == NtFlushInstructionCacheOrigPtr) {
        return DetourNtFlushInstructionCache;
    }
    else if (OrigSyscall == NtQueryInformationProcessOrigPtr) {
        return DetourNtQueryInformationProcess;
    }
    return NULL;
}