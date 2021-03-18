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

static wchar_t IfhMagicFileName[] = L"ifh--";

static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static NtCreateFile_t OriginalNtCreateFile = NULL;

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

	kprintf("[+] falconeye: Loaded.\n");

	// ObCallbacks are used to get a callback when a process creates/
	// duplicates a handle to another process. Both "attacker" process, and
	// "victim" process are stored in OpenProcessMap, if the attacker process
	// 	opens the victim with certain permissions.

	// Perform ObCallback Registration
	status = FEPerformObCallbackRegistration();

	// Let the driver be unloaded gracefully. 
	DriverObject->DriverUnload = DriverUnload;

	OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
	if (!OriginalNtCreateFile)
	{
		kprintf("[-] falconeye: Failed to locate export: %wZ.\n", StringNtCreateFile);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	FindNtBase(OriginalNtCreateFile);
	InitActionHistory();
	GetSyscallAddresses();

	// Initialize infinity hook. Each system call will be redirected to syscall stub.
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

	// Unregister OpenProcess Callback
	FEPerformObCallbackUnregistration();

	// Unload infinity hook gracefully.
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
	if (g_DbgPrintSyscall) {
		kprintf("[+] FalconEye: SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
	}
	
	SaveOriginalFunctionAddress(SystemCallIndex, SystemCallFunction);

	void** DetourAddress = (void **)GetDetourFunction(*SystemCallFunction);
	if (DetourAddress) {
		*SystemCallFunction = DetourAddress;
	}
}