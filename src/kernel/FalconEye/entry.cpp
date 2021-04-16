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
#include "Syscalls.h"
#include "FloatingCodeDetect.h"
#include "Callbacks.h"
#include "ActionHistory.h"
#include "Helper.h"

PVOID64 NtBase;
PVOID64 ntdllBase;
PVOID64 kernel32Base;
PVOID64 kernel32wow64Base;

BOOLEAN bFELoadImageCallbackInstalled = FALSE;
PVOID pKernel32 = NULL;

static wchar_t IfhMagicFileName[] = L"ifh--";

static UNICODE_STRING OpenProcessFilter[NUM_FILTERED_PROCESS] = {	RTL_CONSTANT_STRING(L"Windows\\System32\\csrss.exe"),
												RTL_CONSTANT_STRING(L"Windows\\System32\\lsass.exe"),
												RTL_CONSTANT_STRING(L"Windows\\System32\\services.exe")
												};

static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static NtCreateFile_t OriginalNtCreateFile = NULL;

RTL_GENERIC_TABLE OpenProcessTable;
FEOPTLOCK FeOptLock;

BOOLEAN g_DbgPrintSyscall = FALSE;
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

	alertf("[+] falconeye: Loaded.\n");

	//Initialize lock for dealing with OpenProcessTable
	RtlZeroMemory(&FeOptLock, sizeof(FeOptLock));
	KeInitializeSpinLock(&FeOptLock.lock);
	// Initialize OpenProcessTable
	RtlInitializeGenericTable(&OpenProcessTable, OpenProcessNodeCompare, OpenProcessNodeAllocate, OpenProcessNodeFree, NULL);

	// ObCallbacks are used to get a callback when a process creates/
	// duplicates a handle to another process. Both "attacker" process, and
	// "victim" process are stored in OpenProcessTable, if the attacker process
	// 	opens the victim with certain permissions. However, the OpenProcessTable
	// is referenced only via attacker Pid.

	// Perform ObCallback registration
	status = FEPerformObCallbackRegistration();

	// Perform Thread Create callback registration
	status = FEPerformThreadCallbackRegistration();

	// Perform LoadImage callback registration
	status = FEPerformLoadImageCallbackRegistration();

	//
	// Let the driver be unloaded gracefully. This also turns off 
	// infinity hook.
	//
	DriverObject->DriverUnload = DriverUnload;

	OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
	if (!OriginalNtCreateFile)
	{
		kprintf("[-] falconeye: Failed to locate export: %wZ.\n", StringNtCreateFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	FindNtBase(OriginalNtCreateFile);
	InitActionHistory();
	GetVolumeList();
	// Initialize infinity hook. Each system call will be redirected to syscall stub.
	NTSTATUS Status = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(Status))
	{
		alertf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status);
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

	CleanupActionHistory();

	//
	// Unload infinity hook gracefully.
	IfhRelease();

	// Unregister OpenProcess Callback
	FEPerformObCallbackUnregistration();

	// Unregister Thread Callback
	FEPerformThreadCallbackUnregistration();

	//
	// Unregister LoadImage Callback
	//
	if (bFELoadImageCallbackInstalled == TRUE) {
		PsRemoveLoadImageNotifyRoutine(FELoadImageCallback);
		bFELoadImageCallbackInstalled = FALSE;
	}

	//
	// Cleanup OpenProcessTable
	//
	PVOID node;
	POpenProcessNode tempNode;
	
	KIRQL oldIrql;
	BOOLEAN bDelete = FALSE;
	KeAcquireSpinLock(&FeOptLock.lock, &oldIrql);
	while (!RtlIsGenericTableEmpty(&OpenProcessTable)) {
		node = RtlGetElementGenericTable(&OpenProcessTable, 0);
		tempNode = (POpenProcessNode)node;
		ULONG64 aPID = (ULONG64)tempNode->aPID;
		ULONG64 vPID = (ULONG64)tempNode->vPID;
		bDelete = RtlDeleteElementGenericTable(&OpenProcessTable, node);
		if (!bDelete)
		{
			alertf("[+] falconeye: Delete failed: aPID= %llu vPID= %llu\n", aPID, vPID);
			break;
		}
		tempNode = NULL;
		kprintf("[+] falconeye: Deleting element: aPID= %llu vPID= %llu\n", aPID, vPID);
	}
	KeReleaseSpinLock(&FeOptLock.lock, oldIrql);

	alertf("\n[!] falconeye: Unloading... BYE!\n");
}


/*
*	For each usermode syscall, this stub will be invoked.
*/
void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex,
	_Inout_ void** SystemCallFunction)
{
	if (g_DbgPrintSyscall) {
		kprintf("[+] FalconEye: SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
	}

	SaveOriginalFunctionAddress(SystemCallIndex, SystemCallFunction);

	void** DetourAddress = (void**)GetDetourFunction(SystemCallIndex);
	if (DetourAddress) {
		//kprintf("[+] FalconEye: SYSCALL %lu: DetourAddr 0x%p \n", SystemCallIndex, DetourAddress);
		// If the aPID is present in OpenProcessTable, only then go through detour
		HANDLE aPID = PsGetCurrentProcessId();
		OpenProcessNode node = { aPID, NULL };
		PVOID pFoundEntry = 0;
		KIRQL oldIrql;
		KeAcquireSpinLock(&FeOptLock.lock, &oldIrql);
		pFoundEntry = RtlLookupElementGenericTable(&OpenProcessTable, &node);
		KeReleaseSpinLock(&FeOptLock.lock, oldIrql);
		if (pFoundEntry)
		{
			*SystemCallFunction = DetourAddress;
		}
	}
}

/*
* Function to check whether a given PID needs to be filtered out
*/
BOOLEAN isProcessFiltered()
{	
	BOOLEAN ret = FALSE;
	ULONG size = 512; // Arbitrary, assuming that the process file name should fit
	PUNICODE_STRING filename = (PUNICODE_STRING)ExAllocatePool(NonPagedPool, size);
	if (filename == nullptr)
	{
		//Could not allocate memory to store filename
		return FALSE;
	}
	if (!ZwQueryInformationProcess((HANDLE)-1,
		ProcessImageFileName, // 27
		filename,
		size - sizeof(WCHAR), //Ensure string will be NULL terminated
		NULL))
	{
		for (INT i=0; i < NUM_FILTERED_PROCESS; i++)
		{
			if (compareFilename(filename, OpenProcessFilter[i], FALSE) == 0)
			{
				// kprintf("[+] falconeye: Ignoring OpenProcess for %wZ\n", filename);
				ret = TRUE;
				break;
			}
		}
	}
	return ret;
}

/*
* Function to register LoadImage callback to get kernel32.dll address
*/
NTSTATUS FEPerformLoadImageCallbackRegistration()
{
	NTSTATUS status = PsSetLoadImageNotifyRoutine(FELoadImageCallback);

	bFELoadImageCallbackInstalled = TRUE;
	if (!NT_SUCCESS(status))
	{
		kprintf("[+] falconeye: Installing LoadImage callbacks failed  status 0x%x\n", status);
		bFELoadImageCallbackInstalled = FALSE;
	}
	else
	{
		kprintf("[+] falconeye: LoadImage callback registered successfully\n");
	}
	return status;
}

BOOLEAN CheckModuleInSetWindowsHookHistory(
	PUNICODE_STRING  FullImageName,
	HANDLE ProcessId)
{
	WCHAR module[260] = { 0 };
	RtlCopyMemory(module, FullImageName->Buffer, FullImageName->Length);
	NtUserSWHExEntry* entry = FindNtSetWindowHookExEntry(module);
	if (NULL != entry && entry->Pid != (ULONG64)ProcessId) {
		alertf("[+] FalconEye: Pid %llu loaded %wZ, %p\n", ProcessId, FullImageName);
		alertf("\n[+] FalconEye: **************************Alert**************************: \n"
		"LoadImage callback found %wZ registered by SetWindowsHook; attacker pid %d loaded in victim pid %d\n", 
			FullImageName, entry->Pid, ProcessId);
		alertf("\n");
		ExFreePool(entry);
		return TRUE;
	}
	return FALSE;
}

/*
* Callback function that gets called on ImageLoad Events
* Finds address of kernel32.dll (both 32 and 64 bit), and
* stores it in respective global vars
*/
VOID
FELoadImageCallback(
	PUNICODE_STRING  FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO  ImageInfo)
{
	UNREFERENCED_PARAMETER(ProcessId);
	
	pKernel32 = ImageInfo->ImageBase;
	UNICODE_STRING kernel32 = RTL_CONSTANT_STRING(L"kernel32.dll");
	UNICODE_STRING ntdllStr = RTL_CONSTANT_STRING(L"ntdll.dll");
	
	if (!kernel32Base)
	{
		// Check if the image loaded is 64 bit
		// Note that the bit check cant be done via ImageNtHeaders->OptionalHeaders,
		// because this value would be for the image loaded, and the image is always seen as 64 bit.
		// WOW64 does some magic later

		ULONG_PTR process32Bit = 0;

		if (!ZwQueryInformationProcess((HANDLE)-1,
			ProcessWow64Information, // 0x1A 
			&process32Bit,
			sizeof(process32Bit),
			NULL))
		{
			if (!process32Bit)
			{
				if (compareFilename(FullImageName, kernel32, TRUE) == 0)
				{
					kernel32Base = pKernel32;
					kprintf("[+] falconeye: Kernel32 Base found %wZ, %p\n", FullImageName, pKernel32);
				}
			}
		}
	}
	if (!kernel32wow64Base)
	{
		// Check if the image loaded is 32 bit
		ULONG_PTR process32Bit = 0;
		if (!ZwQueryInformationProcess((HANDLE)-1,
			ProcessWow64Information, // 0x1A 
			&process32Bit,
			sizeof(process32Bit),
			NULL))
		{
			if (process32Bit)
			{
				if (compareFilename(FullImageName, kernel32, TRUE) == 0)
				{
					kernel32wow64Base = pKernel32;
					kprintf("[+] falconeye: Kernel32 WOW64 Base found %wZ, %p\n", FullImageName, pKernel32);
				}
			}
		}
	}
	if (!ntdllBase) {
		if (compareFilename(FullImageName, ntdllStr, TRUE) == 0)
		{
			ntdllBase = ImageInfo->ImageBase;
			kprintf("[+] falconeye: ntdll Base found %wZ, %p\n", FullImageName, ntdllBase);
		}
	}
	if (NULL != FullImageName) {
		CheckModuleInSetWindowsHookHistory(FullImageName, ProcessId);
	}
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
	if ((ULONG64)lhs->aPID < (ULONG64)rhs->aPID)
	{
		return GenericLessThan;
	}
	else if ((ULONG64)lhs->aPID > (ULONG64)rhs->aPID)
	{
		return GenericGreaterThan;
	}
	return GenericEqual;
	/*
	else
	{
		if ((ULONG64)lhs->vPID < (ULONG64)rhs->vPID)
		{
			return GenericLessThan;
		}
		else if ((ULONG64)lhs->vPID > (ULONG64)rhs->vPID)
		{
			return GenericGreaterThan;
		}
		return GenericEqual;
	}
	*/
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