/*
*	Module Name:
*		entry.cpp
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

#include "stdafx.h"
#include "entry.h"
#include "..\libinfinityhook\infinityhook.h"

PVOID64 NtBase;

RTL_GENERIC_TABLE OpenProcessTable;

BOOLEAN bFEObCallbackInstalled = FALSE;
PVOID pCBRegistrationHandle = NULL;
OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
OB_OPERATION_REGISTRATION CBOperationRegistrations[1] = { { 0 } };
UNICODE_STRING CBAltitude = { 0 };

static wchar_t IfhMagicFileName[] = L"ifh--";

static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static NtCreateFile_t OriginalNtCreateFile = NULL;

static UNICODE_STRING StringNtWriteVirtualMemory = RTL_CONSTANT_STRING(L"NtWriteVirtualMemory");
static NtWriteVirtualMemory_t OriginalNtWriteVirtualMemory = NULL;

static FEOPTLOCK FeOptLock;

/*
*	The entry point of the driver. Initializes infinity hook and
*	sets up the driver's unload routine so that it can be gracefully 
*	turned off.
*/
extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;

	//Initialize lock for dealing with OpenProcessTable
	RtlZeroMemory(&FeOptLock, sizeof(FeOptLock));
	KeInitializeSpinLock(&FeOptLock.lock);
	// Initialize OpenProcessTable
	RtlInitializeGenericTable(&OpenProcessTable, OpenProcessNodeCompare, OpenProcessNodeAllocate, OpenProcessNodeFree, NULL);

	// ObCallbacks are used to get a callback when a process creates/
	// duplicates a handle to another process. Both "attacker" process, and
	// "victim" process are stored in OpenProcessTable, if the attacker process
	// 	opens the victim with certain permissions.

	// Perform ObCallback Registration
	status = FEPerformObCallbackRegistration();

	//
	// Figure out when we built this last for debugging purposes.
	//
	kprintf("[+] falconeye: Loaded.\n");

	//
	// Let the driver be unloaded gracefully. This also turns off 
	// infinity hook.
	//
	DriverObject->DriverUnload = DriverUnload;

	//
	// Demo detouring of nt!NtCreateFile.
	//
	OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
	if (!OriginalNtCreateFile)
	{
		kprintf("[-] falconeye: Failed to locate export: %wZ.\n", StringNtCreateFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	// For syscalls not exported, use NtBase and find the offset
	// Use the NtCreateFile address to get Nt base
	UCHAR* It = (UCHAR*)(PVOID64)OriginalNtCreateFile;
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
		kprintf("[+] falconeye: NtBase: %p.\n", NtBase);
	}
	// Find NtWriteVirtualMemoryOffset
	ULONG64 NtWriteVirtualMemoryOffset = FEGetFunctionOffset(&StringNtWriteVirtualMemory);
	OriginalNtWriteVirtualMemory = (NtWriteVirtualMemory_t)((ULONG64)NtBase + NtWriteVirtualMemoryOffset);
	if (OriginalNtWriteVirtualMemory)
	{
		kprintf("[+] falconeye: NtWriteVirtualMemory: %p.\n", OriginalNtWriteVirtualMemory);
	}
	if (!OriginalNtWriteVirtualMemory)
	{
		kprintf("[-] falconeye: Failed to locate export: %wZ.\n", StringNtWriteVirtualMemory);
		//return STATUS_ENTRYPOINT_NOT_FOUND;
	}
	

	//
	// Initialize infinity hook. Each system call will be redirected
	// to our syscall stub.
	//
	NTSTATUS Status = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(Status))
	{
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status);
	}

	return Status;
}

/*
*	Turns off infinity hook.
*/
void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	//
	// Unregister OpenProcess Callback
	//
	if (bFEObCallbackInstalled == TRUE) {
		ObUnRegisterCallbacks(pCBRegistrationHandle);
		pCBRegistrationHandle = NULL;
		bFEObCallbackInstalled = FALSE;
	}

	//
	// Cleanup OpenProcessTable
	//
	PVOID node;
	POpenProcessNode tempNode;
	/*
	for (node = RtlEnumerateGenericTable(&OpenProcessTable, TRUE);
		node != NULL;
		node = RtlEnumerateGenericTable(&OpenProcessTable, TRUE))
	{
		OpenProcessNode tempNode = *(POpenProcessNode)node;
		RtlDeleteElementGenericTable(&OpenProcessTable, &tempNode);
	}
	*/
	KIRQL oldIrql;
	KeAcquireSpinLock(&FeOptLock.lock, &oldIrql);
	while (!RtlIsGenericTableEmpty(&OpenProcessTable)) {
		node = RtlGetElementGenericTable(&OpenProcessTable, 0);
		tempNode = (POpenProcessNode)node;
		ULONG64 aPID = (ULONG64)tempNode->aPID;
		ULONG64 vPID = (ULONG64)tempNode->vPID;
		RtlDeleteElementGenericTable(&OpenProcessTable, node);
		tempNode = NULL;
		kprintf("[+] falconeye: Deleting element: aPID= %llu vPID= %llu\n", aPID, vPID);
	}
	KeReleaseSpinLock(&FeOptLock.lock, oldIrql);
	//
	// Unload infinity hook gracefully.
	//
	IfhRelease();

	kprintf("\n[!] falconeye: Unloading... BYE!\n");
}

/*
*	For each usermode syscall, this stub will be invoked.
*/
void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex, 
	_Inout_ void** SystemCallFunction)
{
	// 
	// Enabling this message gives you VERY verbose logging... and slows
	// down the system. Use it only for debugging.
	//
	
#if 0
	kprintf("[+] infinityhook: SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
#endif

	UNREFERENCED_PARAMETER(SystemCallIndex);

	//
	// In our demo, we care only about nt!NtCreateFile calls.
	//
	if (*SystemCallFunction == OriginalNtCreateFile)
	{
		//
		// We can overwrite the return address on the stack to our detoured
		// NtCreateFile.
		//
		*SystemCallFunction = DetourNtCreateFile;
	}
	else if (*SystemCallFunction == OriginalNtWriteVirtualMemory)
	{
		//
		// We can overwrite the return address on the stack to our detoured
		// NtCreateFile.
		//
		*SystemCallFunction = DetourNtWriteVirtualMemory;
	}
}

/*
*	This function is invoked instead of nt!NtCreateFile. It will 
*	attempt to filter a file by the "magic" file name.
*/
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
	_In_ ULONG EaLength)
{
	//
	// We're going to filter for our "magic" file name.
	//
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName && 
		ObjectAttributes->ObjectName->Buffer)
	{
		//
		// Unicode strings aren't guaranteed to be NULL terminated so
		// we allocate a copy that is.
		//
		PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
		if (ObjectName)
		{
			memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
		
			//
			// Does it contain our special file name?
			//
			if (wcsstr(ObjectName, IfhMagicFileName))
			{
				kprintf("[+] infinityhook: Denying access to file: %wZ.\n", ObjectAttributes->ObjectName);

				ExFreePool(ObjectName);

				//
				// The demo denies access to said file.
				//
				return STATUS_ACCESS_DENIED;
			}

			ExFreePool(ObjectName);
		}
	}

	//
	// We're uninterested, call the original.
	//
	return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

/*
*	This function is invoked instead of nt!NtWriteVirtualMemory. 
*	It will first check the OpenProcessTable for the source, destination
*   pid pair. If present, it will log the pids and the address of buffer
*   to <todo>.
*/

NTSTATUS DetourNtWriteVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ ULONG NumberOfBytesToWrite,
	_Out_opt_ PULONG NumberOfBytesWritten)
{
	// Get PID from the process handle
	PEPROCESS eprocessPtr;
	PVOID pObject;
	HANDLE aPID, vPID;

	
	NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, GENERIC_READ, *PsProcessType, KernelMode, &pObject, NULL);
	if (!NT_SUCCESS(status))
	{
		kprintf("[+] falconeye: ObReferenceObjectByHandle failed  status 0x%x\n", status);
	}
	
	eprocessPtr = (PEPROCESS)pObject;
	vPID = PsGetProcessId(eprocessPtr);
	aPID = PsGetCurrentProcessId();
	
	// If a process is writing to a different process
	if ((ULONG64)aPID != (ULONG64)vPID)
	{
		kprintf("[+] falconeye: NtWriteVirtualMemory AttackerPID: %llu VictimPID: %llu BaseAddress: %p", aPID, vPID, BaseAddress);
	}
	
	return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

/*
* Function to get offset of a given function
* This offset is either hardcoded or parsed from symbols
*/
ULONG64 FEGetFunctionOffset(
	PUNICODE_STRING funcName
)
{
	ULONG64 offset = 0;
	if(RtlEqualUnicodeString(funcName, &StringNtWriteVirtualMemory, TRUE))
	{
		offset = 0x6de8d0;
	}
	return offset;
}

/*
* Function to register obcallbacks to capture suspicious OpenProcess Events 
*/
NTSTATUS FEPerformObCallbackRegistration()
{
	CBOperationRegistrations[0].ObjectType = PsProcessType;
	CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
	CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	CBOperationRegistrations[0].PreOperation = FEOpenProcessCallback;
	//CBOperationRegistrations[0].PostOperation = CBTdPostOperationCallback;
	CBOperationRegistrations[0].PostOperation = NULL;

	RtlInitUnicodeString(&CBAltitude, L"1337");

	CBObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	CBObRegistration.OperationRegistrationCount = 1;
	CBObRegistration.Altitude = CBAltitude;
	CBObRegistration.RegistrationContext = NULL;
	CBObRegistration.OperationRegistration = CBOperationRegistrations;

	NTSTATUS status = ObRegisterCallbacks(
		&CBObRegistration,
		&pCBRegistrationHandle       // save the registration handle to remove callbacks later
	);

	bFEObCallbackInstalled = TRUE;
	if (!NT_SUCCESS(status))
	{
		kprintf("[+] falconeye: installing OB callbacks failed  status 0x%x\n", status);
		bFEObCallbackInstalled = FALSE;
	}
	return status;
}

/*
* Callback function that gets called on OpenProcess Events
* Populates OpenProcessTable
*/
OB_PREOP_CALLBACK_STATUS
FEOpenProcessCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	//UNREFERENCED_PARAMETER(PreInfo);
	HANDLE curPID, openedPID;
	//ACCESS_MASK suspiciousMask;
	//NTSTATUS status;

	if (PreInfo->ObjectType == *PsProcessType)
	{
		curPID = PsGetCurrentProcessId();
		PEPROCESS OpenedProcess = (PEPROCESS)PreInfo->Object;
		openedPID = PsGetProcessId(OpenedProcess);

		//If a process is opening another process and the source process is not SYSTEM
		if (curPID != openedPID && (UINT_PTR)curPID != 4)
		{
			//Not a kernel operation
			if (PreInfo->KernelHandle != 1)
			{
				//If PROCESS_VM_WRITE Access is requested
				if ((PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & 0x0020) == 0x0020)
				{
					// Add "attacker" and "victim" PID to OpenProcessTable
					OpenProcessNode node = { curPID, openedPID };
					BOOLEAN newElement = FALSE;
					PVOID pFoundEntry = 0;
					KIRQL oldIrql;
					KeAcquireSpinLock(&FeOptLock.lock, &oldIrql);
					pFoundEntry = RtlInsertElementGenericTable(&OpenProcessTable, &node, sizeof(OpenProcessNode), &newElement);
					if (!pFoundEntry)
					{
						kprintf("[+] falconeye: Unable to insert into OpenProcessTable\n");
					}
					KeReleaseSpinLock(&FeOptLock.lock, oldIrql);
					kprintf("[+] falconeye: Suspicious process %llu is trying to open process %llu with write permissions.\n",
						(ULONG64)curPID,
						(ULONG64)openedPID);
				}
			}

		}
	}
	return OB_PREOP_SUCCESS;
}

/*
* This function is a callback for generic compare routine for OpenProcessTable
*/
RTL_GENERIC_COMPARE_RESULTS OpenProcessNodeCompare(
	_In_ PRTL_GENERIC_TABLE Table,
	_In_ PVOID Lhs,
	_In_ PVOID Rhs
)
{
	UNREFERENCED_PARAMETER(Table);

	OpenProcessNode* lhs = (OpenProcessNode*)Lhs;
	OpenProcessNode* rhs = (OpenProcessNode*)Rhs;
	if ((ULONG64)&lhs->aPID < (ULONG64)&rhs->aPID)
	{
		return GenericLessThan;
	}
	else if ((ULONG64)&lhs->aPID > (ULONG64)&rhs->aPID)
	{
		return GenericGreaterThan;
	}
	else
	{
		if ((ULONG64)&lhs->vPID < (ULONG64)&rhs->vPID)
		{
			return GenericLessThan;
		}
		else if ((ULONG64)&lhs->vPID > (ULONG64)&rhs->vPID)
		{
			return GenericGreaterThan;
		}
		return GenericEqual;
	}
}

/*
* This function is a callback for generic allocate routine for OpenProcessTable
*/
PVOID OpenProcessNodeAllocate(
	_In_ PRTL_GENERIC_TABLE Table,
	_In_ CLONG ByteSize
)
{
	UNREFERENCED_PARAMETER(Table);

	return ExAllocatePoolWithTag(PagedPool, ByteSize, FE_TABLE_ENTRY_TAG);
}

/*
* This function is a callback for generic free routine for OpenProcessTable
*/
VOID OpenProcessNodeFree(
	_In_ PRTL_GENERIC_TABLE Table,
	_In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Entry
)
{
	UNREFERENCED_PARAMETER(Table);

	ExFreePoolWithTag(Entry, FE_TABLE_ENTRY_TAG);
}