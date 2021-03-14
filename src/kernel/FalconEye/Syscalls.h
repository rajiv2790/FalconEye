#pragma once
#include "NtDefs.h"

typedef NTSTATUS(*NtAddAtomEx_t)(
		_In_reads_bytes_opt_(Length) PWSTR AtomName,
		_In_ ULONG Length,
		_Out_opt_ PRTL_ATOM Atom,
		_In_ ULONG Flags
	);

typedef NTSTATUS(*NtWriteVirtualMemory_t)(
	_In_ HANDLE               ProcessHandle,
	_In_ PVOID                BaseAddress,
	_In_ PVOID                Buffer,
	_In_ ULONG                NumberOfBytesToWrite,
	_Out_opt_ PULONG          NumberOfBytesWritten);

typedef NTSTATUS(*NtSuspendThread_t)(
	_In_ HANDLE               ThreadHandle,
	_Out_opt_ PULONG          PreviousSuspendCount);

typedef NTSTATUS(*NtMapViewOfSection_t)(
	_In_ HANDLE               SectionHandle,
	_In_ HANDLE               ProcessHandle,
	_In_ _Out_opt_ PVOID*	  BaseAddress,
	_In_ ULONG                ZeroBits,
	_In_ ULONG                CommitSize,
	_In_ _Out_opt_ PLARGE_INTEGER   SectionOffset,
	_In_ _Out_opt_ PULONG           ViewSize,
	_In_ SECTION_INHERIT	  InheritDisposition,
	_In_ ULONG                AllocationType,
	_In_ ULONG                Protect);

typedef NTSTATUS(*NtUnmapViewOfSection_t)(
	_In_ HANDLE               ProcessHandle,
	_In_ PVOID                BaseAddress);

typedef NTSTATUS(*NtCreateThread_t)(
	_Out_ PHANDLE             ThreadHandle,
	_In_ ACCESS_MASK          DesiredAccess,
	_In_ POBJECT_ATTRIBUTES   ObjectAttributes,
	_In_ HANDLE               ProcessHandle,
	_Out_ PCLIENT_ID          ClientId,
	_In_ PCONTEXT             ThreadContext,
	_In_ PINITIAL_TEB         InitialTeb,
	_In_ BOOLEAN              CreateSuspended);

typedef NTSTATUS(*NtResumeThread_t)(
	_In_ HANDLE             ThreadHandle,
	_Out_opt_ PULONG        SuspendCount);

typedef NTSTATUS(*NtQueueApcThread_t)(
	_In_ HANDLE               ThreadHandle,
	_In_ PIO_APC_ROUTINE      ApcRoutine,
	_In_ PVOID                ApcRoutineContext,
	_In_ PIO_STATUS_BLOCK     ApcStatusBlock,
	_In_ ULONG                ApcReserved);

typedef NTSTATUS(*NtSetContextThread_t)(
	_In_ HANDLE               ThreadHandle,
	_In_ PCONTEXT             Context);

typedef NTSTATUS(*NtSuspendProcess_t)(
	_In_ HANDLE ProcessHandle);

typedef NTSTATUS(*NtSetInformationProcess_t)(
	_In_ HANDLE               ProcessHandle,
	_In_ PROCESSINFOCLASS	  ProcessInformationClass,
	_In_ PVOID                ProcessInformation,
	_In_ ULONG                ProcessInformationLength);

typedef NTSTATUS(*NtConnectPort_t)(
	_Out_ PHANDLE             ClientPortHandle,
	_In_ PUNICODE_STRING      ServerPortName,
	_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	_In_ _Out_opt_ PLPC_SECTION_OWNER_MEMORY ClientSharedMemory,
	_Out_opt_ PLPC_SECTION_MEMORY ServerSharedMemory,
	_Out_opt_ PULONG              MaximumMessageLength,
	_In_ PVOID                ConnectionInfo,
	_In_ PULONG               ConnectionInfoLength);

typedef NTSTATUS(*NtFlushInstructionCache_t)(
	_In_ HANDLE               ProcessHandle,
	_In_ PVOID                BaseAddress,
	_In_ ULONG                NumberOfBytesToFlush);

typedef NTSTATUS(*NtQueryInformationProcess_t)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

typedef BOOL(*NtUserSetProp_t)(
	_In_ HWND hWnd,
	_In_ ATOM Atom,
	_In_ HANDLE Data);

typedef HHOOK(*NtUserSetWindowsHookEx_t)(
	HINSTANCE Mod,
	PUNICODE_STRING UnsafeModuleName,
	DWORD ThreadId,
	int HookId,
	HOOKPROC HookProc,
	BOOL Ansi);

typedef LONG_PTR(*NtUserSetWindowLongPtr_t)(
	HWND hWnd,
	DWORD Index,
	LONG_PTR NewValue,
	BOOL Ansi);

typedef BOOL(*NtUserPostMessage_t)(
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam);

typedef NTSTATUS(*NtUserMessageCall_t)(
	HWND hWnd, 
	UINT msg, 
	WPARAM wParam, 
	LPARAM lParam, 
	ULONG_PTR ResultInfo, 
	DWORD dwType, 
	BOOLEAN bAnsi);

typedef BOOL(*NtUserPostThreadMessage_t)(
	DWORD idThread,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam);

typedef ULONG(*NtUserSendInput_t)(
	IN UINT cInputs, // number of input in the array
	IN LPINPUT pInputs, // array of inputs
	IN int cbSize);

// exports
extern PVOID64 NtBaseAddress;
NTSTATUS GetSyscallAddresses();
PVOID64 FindNtBase(PVOID64 start);
PVOID UpdateSystemCallFunction(PVOID OrigSyscall);

// defs for API strings and addresses
#define DEF_USTR_SYSCALL(_name_) \
    static UNICODE_STRING   _name_##Str = RTL_CONSTANT_STRING(L#_name_)

#define DEF_ORIG_SYSCALL_PTR(_name_) \
    static _name_##_t _name_##OrigPtr = NULL;

#define GET_SYSCALL_ADDR(_name_) \
    _name_##OrigPtr = (_name_##_t)MmGetSystemRoutineAddress(&_name_##Str); \
    if (!_name_##OrigPtr) { \
        kprintf("[-] : Failed to locate export: %wZ.\n", _name_##Str); \
        status = STATUS_ENTRYPOINT_NOT_FOUND; \
    } else { \
        kprintf("[-] : For: %wZ Address: %p.\n", _name_##Str, _name_##OrigPtr); \
    }

// add NtBase + Offset
#define ADD_SYSCALL_ADDR(_name_) \
	_name_##OrigPtr = (_name_##_t)((PUCHAR)NtBaseAddress + _name_##_Offset)