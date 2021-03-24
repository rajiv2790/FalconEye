/*
*	Module Name:
*		entry.h
*
*	Abstract:
*		Sample driver that implements infinity hook to detour
*		system calls.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*		
*/

#pragma once

#define FE_TABLE_ENTRY_TAG                   'eFeA'
#define NUM_FILTERED_PROCESS				 3

///
/// Structures and typedefs.
///

typedef NTSTATUS(*NtCreateFile_t)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength);

typedef NTSTATUS(*NtWriteVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ ULONG NumberOfBytesToWrite,
	_Out_opt_ PULONG NumberOfBytesWritten);

typedef struct _OpenProcessNode {
	HANDLE aPID;
	HANDLE vPID;
} OpenProcessNode, * POpenProcessNode;

// OPT == OpenProcessTable
typedef struct _FE_OPT_LOCK {
	KSPIN_LOCK lock;
} FEOPTLOCK, *PFEOPTLOCK;

///
/// Forward declarations.
///

extern "C" DRIVER_INITIALIZE DriverEntry;

void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject);

void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex, 
	_Inout_ void** SystemCallFunction);

OB_PREOP_CALLBACK_STATUS
FEOpenProcessCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
);

NTSTATUS FEPerformLoadImageCallbackRegistration();

VOID
FELoadImageCallback(
	PUNICODE_STRING  FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO  ImageInfo);

RTL_GENERIC_COMPARE_RESULTS OpenProcessNodeCompare(
	_In_ PRTL_GENERIC_TABLE Table,
	_In_ PVOID Lhs,
	_In_ PVOID Rhs
);

PVOID OpenProcessNodeAllocate(
	_In_ PRTL_GENERIC_TABLE Table,
	_In_ CLONG ByteSize
);

VOID OpenProcessNodeFree(
	_In_ PRTL_GENERIC_TABLE Table,
	_In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Entry
);

///
/// Hooks
///

NTSTATUS DetourNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength);

NTSTATUS DetourNtWriteVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ ULONG NumberOfBytesToWrite,
	_Out_opt_ PULONG NumberOfBytesWritten);

///
/// Utility Functions
/// 

ULONG64 FEGetFunctionOffset(
	PUNICODE_STRING funcName);

LONG compareFilename(
	PUNICODE_STRING  FullImageName,
	UNICODE_STRING str,
	BOOLEAN bGetLastToken);

BOOLEAN isProcessFiltered();

///
/// Unexported APIs
///

extern "C" NTSTATUS ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);
