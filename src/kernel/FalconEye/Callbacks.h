#pragma once
NTSTATUS FEPerformObCallbackRegistration();
NTSTATUS FEPerformObCallbackUnregistration();
NTSTATUS FEPerformThreadCallbackRegistration();
NTSTATUS FEPerformThreadCallbackUnregistration();

OB_PREOP_CALLBACK_STATUS
FEOpenProcessCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
);

VOID CreateThreadNotifyRoutineEx(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
);