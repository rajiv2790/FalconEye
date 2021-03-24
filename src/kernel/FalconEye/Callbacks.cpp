#include "stdafx.h"
#include "entry.h"

BOOLEAN bFEObCallbackInstalled = FALSE;
PVOID pCBRegistrationHandle = NULL;
OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
OB_OPERATION_REGISTRATION CBOperationRegistrations[1] = { { 0 } };
UNICODE_STRING CBAltitude = { 0 };

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
	return OB_PREOP_SUCCESS;
}