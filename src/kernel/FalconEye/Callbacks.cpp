#include "stdafx.h"
#include "entry.h"
#include "Callbacks.h"
#include "Helper.h"
#include "FloatingCodeDetect.h"

BOOLEAN bFEObCallbackInstalled = FALSE;
PVOID pCBRegistrationHandle = NULL;
OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
OB_OPERATION_REGISTRATION CBOperationRegistrations[2] = { { 0 }, { 0 } };
UNICODE_STRING CBAltitude = { 0 };

BOOLEAN bFEThreadCallbackInstalled = FALSE;

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

	CBOperationRegistrations[1].ObjectType = PsThreadType;
	CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
	CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	CBOperationRegistrations[1].PreOperation = FEOpenProcessCallback;
	//CBOperationRegistrations[0].PostOperation = CBTdPostOperationCallback;
	CBOperationRegistrations[0].PostOperation = NULL;

	RtlInitUnicodeString(&CBAltitude, L"1337");

	CBObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	CBObRegistration.OperationRegistrationCount = 2;
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
		kprintf("[+] falconeye: installing OB callbacks failed status 0x%x\n", status);
		bFEObCallbackInstalled = FALSE;
	}
	else
	{
		kprintf("[+] falconeye: OB callback registered successfully\n");
	}
	return status;
}

NTSTATUS FEPerformObCallbackUnregistration()
{
	if (bFEObCallbackInstalled == TRUE) {
		ObUnRegisterCallbacks(pCBRegistrationHandle);
		pCBRegistrationHandle = NULL;
		bFEObCallbackInstalled = FALSE;
	}
	return STATUS_SUCCESS;
}

/*
* Function to check and add a pair of attacker and victim process
* to OpenProcessTable
*/
void AddToOPT(POB_PRE_OPERATION_INFORMATION PreInfo, HANDLE openedPID)
{
	HANDLE curPID;
	curPID = PsGetCurrentProcessId();

	//If a process is opening another process and the source process is not SYSTEM
	if (curPID != openedPID && (UINT_PTR)curPID != 4)
	{
		//Not a kernel operation
		if (PreInfo->KernelHandle != 1)
		{
			//If PROCESS_VM_WRITE Access is requested
			if ((PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & 0x0020) == 0x0020)
			{
				//Check if the "attacker" process needs to be filtered
				if (!isProcessFiltered())
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
}

/*
* Callback function that gets called on OpenProcess Events
* Populates OpenProcessMap
*/
OB_PREOP_CALLBACK_STATUS
FEOpenProcessCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(PreInfo);
	HANDLE openedPID;
	//ACCESS_MASK suspiciousMask;
	//NTSTATUS status;

	if (PreInfo->ObjectType == *PsProcessType)
	{
		PEPROCESS OpenedProcess = (PEPROCESS)PreInfo->Object;
		openedPID = PsGetProcessId(OpenedProcess);
		AddToOPT(PreInfo, openedPID);
	}
	if (PreInfo->ObjectType == *PsThreadType)
	{
		openedPID = PsGetThreadProcessId((PETHREAD)PreInfo->Object);
		AddToOPT(PreInfo, openedPID);
	}
	
	return OB_PREOP_SUCCESS;
}

/*
* Function to register thread create callback
*/
NTSTATUS FEPerformThreadCallbackRegistration()
{
	NTSTATUS status;
	status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, (PVOID)&CreateThreadNotifyRoutineEx);

	if (!NT_SUCCESS(status))
	{
		kprintf("[+] falconeye: installing Thread callbacks failed status 0x%x\n", status);
		bFEThreadCallbackInstalled = FALSE;
	}
	else
	{
		kprintf("[+] falconeye: Thread callback registered successfully\n");
		bFEThreadCallbackInstalled = TRUE;
	}
	return status;
}

NTSTATUS FEPerformThreadCallbackUnregistration()
{
	if (bFEThreadCallbackInstalled == TRUE)
	{
		PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)&CreateThreadNotifyRoutineEx);
		bFEThreadCallbackInstalled = FALSE;
	}
	return STATUS_SUCCESS;
}

/*
* Callback function that gets called on Thread Create Events
* 
*/
VOID CreateThreadNotifyRoutineEx(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
)
{
	ULONG64 startAddress;
	NTSTATUS status;

	// If Thread created as opposed to deleted
	if (Create == TRUE)
	{	
		// Get the start address of the thread
		status = ZwQueryInformationThread(ZwCurrentThread(), ThreadQuerySetWin32StartAddress, &startAddress, sizeof(ULONG64), NULL);
		if (!NT_SUCCESS(status))
		{
			kprintf("[+] falconeye: Getting Thread start address failed status 0x%x\n", status);
		}
		else
		{
			if (CheckMemImageByAddress((PVOID)startAddress, NULL))
			{
				alertf("[+] FalconEye: CreateThreadNotifyRoutineEx thread %llu in process %llu and start address %p\n",
					(PVOID)ThreadId, (PVOID)ProcessId, startAddress);
				alertf("\n[+] FalconEye: **************************Alert**************************\n"
					"Suspicious thread %llu in victim pid %llu. FloatingCode: start address %p \n", 
					(PVOID)ThreadId,
					(PVOID)ProcessId,
					startAddress);
				alertf("\n");
			}
			if (eLoadLibrary == IsKnownAPIOffset((PCHAR)startAddress)) {
				alertf("[+] FalconEye: CreateThreadNotifyRoutineEx thread %llu in process %llu and start address %p\n",
					(PVOID)ThreadId, (PVOID)ProcessId, startAddress);
				alertf("\n[+] FalconEye: **************************Alert**************************\n"
					"Thread in victim pid %d with tid %d StartAddress %p pointing to LoadLibrary\n",
					(PVOID)ProcessId, 
					(PVOID)ThreadId,
					startAddress);
				alertf("\n");
			}
		}
	}
}