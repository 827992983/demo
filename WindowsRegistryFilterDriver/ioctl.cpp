#include <ntifs.h>
#include "ioctl.h"


UNICODE_STRING g_PolicyKeyArray[] = {
	RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\BootExecute"),
	RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\System\\ControlSet001\\Control\\Session Manager\\BootExecute"),
	RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\System\\ControlSet002\\Control\\Session Manager\\BootExecute"),
	RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\System\\ControlSet003\\Control\\Session Manager\\BootExecute")
};
ULONG g_PolicyKeyCount = sizeof(g_PolicyKeyArray) / sizeof(UNICODE_STRING);

typedef PCHAR(*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);

PCHAR GetProcessImagePath(PEPROCESS processId)
{
	static GET_PROCESS_IMAGE_NAME PsGetProcessImageFileName = NULL;
	UNICODE_STRING FuncName = RTL_CONSTANT_STRING(L"PsGetProcessImageFileName");
	PCHAR pImageName = NULL;

	if (NULL == PsGetProcessImageFileName)
	{
		PsGetProcessImageFileName = (GET_PROCESS_IMAGE_NAME)MmGetSystemRoutineAddress(&FuncName);
		if (PsGetProcessImageFileName == NULL)
			return pImageName;
	}

	pImageName = PsGetProcessImageFileName(processId);

	return pImageName;
}

BOOLEAN IsAllowProcess(void)
{
	PEPROCESS struProcess;
	PCHAR pchImageFileName;
	NTSTATUS Status;
	DWORD Len;
	PFILE_OBJECT FileObject;

	struProcess = IoGetCurrentProcess();

	pchImageFileName = GetProcessImagePath(struProcess);

	if (pchImageFileName && (_stricmp(pchImageFileName, "regctrl.exe") == 0)) {
		return TRUE;
	}

	return FALSE;
}

LPCWSTR GetNotifyClassString(IN REG_NOTIFY_CLASS NotifyClass);

BOOLEAN CheckPolicy(PUNICODE_STRING KeyFullPath)
{
	BOOLEAN bMatched = FALSE;
	ULONG ulIdx;

	for (ulIdx = 0; ulIdx < g_PolicyKeyCount; ulIdx++)
	{
		if (RtlEqualUnicodeString(KeyFullPath, &g_PolicyKeyArray[ulIdx], TRUE)) {
			bMatched = TRUE;
			break;
		}
	}

	if (bMatched)
	{
		DbgPrint("Regmon pid(%x) and tid(%x) Block %wZ\n", PsGetCurrentProcessId(), PsGetCurrentThreadId(), KeyFullPath);
	}
	else {
		DbgPrint("Regmon Block %wZ\n", KeyFullPath);
	}

	return bMatched;
}

BOOLEAN CheckObjectAndPolicy(PCALLBACK_CONTEXT Ctx, PVOID RootObject, PUNICODE_STRING CompleteName)
{
	PUNICODE_STRING puniRootObjectName;
	ULONG_PTR pulRootObjectID;
	BOOLEAN bMatched = FALSE;
	NTSTATUS Status;
	UNICODE_STRING uniKeyPath = { 0 };

	if (RootObject)
	{
		if (!NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&Ctx->Cookie, RootObject, &pulRootObjectID, (PCUNICODE_STRING*)&puniRootObjectName)))
		{
			DbgPrint("CmCallbackGetKeyObjectID : (%x) was fail..\n", Status);
			goto Exit;
		}

		if (CompleteName == NULL)
		{
			bMatched = CheckPolicy(puniRootObjectName);
		}
		else
		{
			if (CompleteName->Length && CompleteName->Buffer)
			{

				uniKeyPath.MaximumLength = puniRootObjectName->Length + CompleteName->Length + (sizeof(WCHAR) * 2);

				uniKeyPath.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, uniKeyPath.MaximumLength, 'Tag1');

				if (!uniKeyPath.Buffer)
				{
					DbgPrint("ExAllocatePool was Fail..\n");
					goto Exit;
				}

				swprintf(uniKeyPath.Buffer, L"%wZ\\%wZ", puniRootObjectName, CompleteName);
				uniKeyPath.Length = puniRootObjectName->Length + CompleteName->Length + (sizeof(WCHAR));

				bMatched = CheckPolicy(&uniKeyPath);;
			}
			else
			{

				bMatched = CheckPolicy(puniRootObjectName);
			}

		}
	}
	else
	{
		DbgPrint("%ws\n", CompleteName->Buffer);
		bMatched = CheckPolicy(CompleteName);
	}

Exit:

	if (uniKeyPath.Buffer)
	{
		ExFreePoolWithTag(uniKeyPath.Buffer, 'Tag1');
	}
	return bMatched;
}

NTSTATUS Callback(IN PVOID CallbackContext, IN PVOID Argument1, IN PVOID Argument2)
{

	NTSTATUS Status = STATUS_SUCCESS;
	REG_NOTIFY_CLASS NotifyClass;
	PCALLBACK_CONTEXT CallbackCtx;

	CallbackCtx = (PCALLBACK_CONTEXT)CallbackContext;
	NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	InfoPrint("\tCallback: Altitude-%S, NotifyClass-%S.",
		CallbackCtx->AltitudeBuffer,
		GetNotifyClassString(NotifyClass));

	if (IsAllowProcess()) {
		ErrorPrint("\tCallback: Current Process is Allowed.");
		return STATUS_SUCCESS;
	}

	if (Argument2 == NULL) {
		ErrorPrint("\tCallback: Argument 2 unexpectedly 0. Filter will "
			"abort and return success.");
		return STATUS_SUCCESS;
	}

	switch (CallbackCtx->CallbackMode) {
	case CALLBACK_MODE_PRE_NOTIFICATION_BLOCK:
		Status = CallbackPreNotificationBlock(CallbackCtx, NotifyClass, Argument2);
		break;
	case CALLBACK_MODE_PRE_NOTIFICATION_BYPASS:
		break;
	default:
		ErrorPrint("Unknown Callback Mode: %d", CallbackCtx->CallbackMode);
		Status = STATUS_INVALID_PARAMETER;
	}


	return Status;

}


NTSTATUS RegisterCallback(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IrpStack;
	ULONG InputBufferLength;
	ULONG OutputBufferLength;
	PREGISTER_CALLBACK_INPUT  RegisterCallbackInput;
	PREGISTER_CALLBACK_OUTPUT RegisterCallbackOutput;
	PCALLBACK_CONTEXT CallbackCtx = NULL;

	IrpStack = IoGetCurrentIrpStackLocation(Irp);

	InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
	OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	if ((InputBufferLength < sizeof(REGISTER_CALLBACK_INPUT)) ||
		(OutputBufferLength < sizeof(REGISTER_CALLBACK_OUTPUT))) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	RegisterCallbackInput = (PREGISTER_CALLBACK_INPUT)Irp->AssociatedIrp.SystemBuffer;

	CallbackCtx = (PCALLBACK_CONTEXT)CreateCallbackContext(RegisterCallbackInput->CallbackMode,
		RegisterCallbackInput->Altitude);

	if (CallbackCtx == NULL) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	Status = CmRegisterCallbackEx(Callback,
		&CallbackCtx->Altitude,
		DeviceObject->DriverObject,
		(PVOID)CallbackCtx,
		&CallbackCtx->Cookie,
		NULL);
	if (!NT_SUCCESS(Status)) {
		ErrorPrint("CmRegisterCallback failed. Status 0x%x", Status);
		goto Exit;
	}

	if (!InsertCallbackContext(CallbackCtx)) {
		Status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}

	RegisterCallbackOutput = (PREGISTER_CALLBACK_OUTPUT)Irp->AssociatedIrp.SystemBuffer;
	RegisterCallbackOutput->Cookie = CallbackCtx->Cookie;
	Irp->IoStatus.Information = sizeof(REGISTER_CALLBACK_OUTPUT);

Exit:
	if (!NT_SUCCESS(Status)) {
		ErrorPrint("RegisterCallback failed. Status 0x%x", Status);
		if (CallbackCtx != NULL) {
			DeleteCallbackContext(CallbackCtx);
		}
	}
	else {
		InfoPrint("RegisterCallback succeeded");
	}

	return Status;
}

NTSTATUS UnRegisterCallback(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IrpStack;
	ULONG InputBufferLength;
	PUNREGISTER_CALLBACK_INPUT UnRegisterCallbackInput;
	PCALLBACK_CONTEXT CallbackCtx;

	UNREFERENCED_PARAMETER(DeviceObject);

	//
	// Get the input buffer and check its size
	//

	IrpStack = IoGetCurrentIrpStackLocation(Irp);

	InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

	if (InputBufferLength < sizeof(UNREGISTER_CALLBACK_INPUT)) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	UnRegisterCallbackInput = (PUNREGISTER_CALLBACK_INPUT)Irp->AssociatedIrp.SystemBuffer;

	//
	// Unregister the callback with the cookie
	//

	Status = CmUnRegisterCallback(UnRegisterCallbackInput->Cookie);

	if (!NT_SUCCESS(Status)) {
		ErrorPrint("CmUnRegisterCallback failed. Status 0x%x", Status);
		goto Exit;
	}

	//
	// Free the callback context buffer
	//
	CallbackCtx = FindAndRemoveCallbackContext(UnRegisterCallbackInput->Cookie);
	if (CallbackCtx != NULL) {
		DeleteCallbackContext(CallbackCtx);
	}

Exit:

	if (!NT_SUCCESS(Status)) {
		ErrorPrint("UnRegisterCallback failed. Status 0x%x", Status);
	}
	else {
		InfoPrint("UnRegisterCallback succeeded");
	}
	InfoPrint("");

	return Status;

}


NTSTATUS GetCallbackVersion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IrpStack;
	ULONG OutputBufferLength;
	PGET_CALLBACK_VERSION_OUTPUT GetCallbackVersionOutput;

	UNREFERENCED_PARAMETER(DeviceObject);

	IrpStack = IoGetCurrentIrpStackLocation(Irp);

	OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	if (OutputBufferLength < sizeof(GET_CALLBACK_VERSION_OUTPUT)) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	GetCallbackVersionOutput = (PGET_CALLBACK_VERSION_OUTPUT)Irp->AssociatedIrp.SystemBuffer;

	CmGetCallbackVersion(&GetCallbackVersionOutput->MajorVersion,
		&GetCallbackVersionOutput->MinorVersion);

	Irp->IoStatus.Information = sizeof(GET_CALLBACK_VERSION_OUTPUT);

Exit:

	if (!NT_SUCCESS(Status)) {
		ErrorPrint("GetCallbackVersion failed. Status 0x%x", Status);
	}
	else {
		InfoPrint("GetCallbackVersion succeeded");
	}

	return Status;
}


LPCWSTR GetNotifyClassString(IN REG_NOTIFY_CLASS NotifyClass)
{
	switch (NotifyClass) {
	case RegNtPreDeleteKey:                 return L"RegNtPreDeleteKey";
	case RegNtPreSetValueKey:               return L"RegNtPreSetValueKey";
	case RegNtPreDeleteValueKey:            return L"RegNtPreDeleteValueKey";
	case RegNtPreSetInformationKey:         return L"RegNtPreSetInformationKey";
	case RegNtPreRenameKey:                 return L"RegNtPreRenameKey";
	case RegNtPreEnumerateKey:              return L"RegNtPreEnumerateKey";
	case RegNtPreEnumerateValueKey:         return L"RegNtPreEnumerateValueKey";
	case RegNtPreQueryKey:                  return L"RegNtPreQueryKey";
	case RegNtPreQueryValueKey:             return L"RegNtPreQueryValueKey";
	case RegNtPreQueryMultipleValueKey:     return L"RegNtPreQueryMultipleValueKey";
	case RegNtPreKeyHandleClose:            return L"RegNtPreKeyHandleClose";
	case RegNtPreCreateKeyEx:               return L"RegNtPreCreateKeyEx";
	case RegNtPreOpenKeyEx:                 return L"RegNtPreOpenKeyEx";
	case RegNtPreFlushKey:                  return L"RegNtPreFlushKey";
	case RegNtPreLoadKey:                   return L"RegNtPreLoadKey";
	case RegNtPreUnLoadKey:                 return L"RegNtPreUnLoadKey";
	case RegNtPreQueryKeySecurity:          return L"RegNtPreQueryKeySecurity";
	case RegNtPreSetKeySecurity:            return L"RegNtPreSetKeySecurity";
	case RegNtPreRestoreKey:                return L"RegNtPreRestoreKey";
	case RegNtPreSaveKey:                   return L"RegNtPreSaveKey";
	case RegNtPreReplaceKey:                return L"RegNtPreReplaceKey";

	case RegNtPostDeleteKey:                return L"RegNtPostDeleteKey";
	case RegNtPostSetValueKey:              return L"RegNtPostSetValueKey";
	case RegNtPostDeleteValueKey:           return L"RegNtPostDeleteValueKey";
	case RegNtPostSetInformationKey:        return L"RegNtPostSetInformationKey";
	case RegNtPostRenameKey:                return L"RegNtPostRenameKey";
	case RegNtPostEnumerateKey:             return L"RegNtPostEnumerateKey";
	case RegNtPostEnumerateValueKey:        return L"RegNtPostEnumerateValueKey";
	case RegNtPostQueryKey:                 return L"RegNtPostQueryKey";
	case RegNtPostQueryValueKey:            return L"RegNtPostQueryValueKey";
	case RegNtPostQueryMultipleValueKey:    return L"RegNtPostQueryMultipleValueKey";
	case RegNtPostKeyHandleClose:           return L"RegNtPostKeyHandleClose";
	case RegNtPostCreateKeyEx:              return L"RegNtPostCreateKeyEx";
	case RegNtPostOpenKeyEx:                return L"RegNtPostOpenKeyEx";
	case RegNtPostFlushKey:                 return L"RegNtPostFlushKey";
	case RegNtPostLoadKey:                  return L"RegNtPostLoadKey";
	case RegNtPostUnLoadKey:                return L"RegNtPostUnLoadKey";
	case RegNtPostQueryKeySecurity:         return L"RegNtPostQueryKeySecurity";
	case RegNtPostSetKeySecurity:           return L"RegNtPostSetKeySecurity";
	case RegNtPostRestoreKey:               return L"RegNtPostRestoreKey";
	case RegNtPostSaveKey:                  return L"RegNtPostSaveKey";
	case RegNtPostReplaceKey:               return L"RegNtPostReplaceKey";

	case RegNtCallbackObjectContextCleanup: return L"RegNtCallbackObjectContextCleanup";

	default:
		return L"Unsupported REG_NOTIFY_CLASS";
	}
}

NTSTATUS DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION IrpStack;
	ULONG Ioctl;
	NTSTATUS Status;

	UNREFERENCED_PARAMETER(DeviceObject);

	Status = STATUS_SUCCESS;

	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (Ioctl)
	{
	case IOCTL_REGISTER_CALLBACK:
		Status = RegisterCallback(DeviceObject, Irp);
		break;

	case IOCTL_UNREGISTER_CALLBACK:
		Status = UnRegisterCallback(DeviceObject, Irp);
		break;

	case IOCTL_GET_CALLBACK_VERSION:
		Status = GetCallbackVersion(DeviceObject, Irp);
		break;

	default:
		break;
	}


	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;

}

FAST_MUTEX g_CallbackCtxListLock;
LIST_ENTRY g_CallbackCtxListHead;
USHORT g_NumCallbackCtxListEntries;

PVOID CreateCallbackContext(IN CALLBACK_MODE CallbackMode, IN PCWSTR AltitudeString)
{

	PCALLBACK_CONTEXT CallbackCtx = NULL;
	NTSTATUS Status;
	BOOLEAN Success = FALSE;

	CallbackCtx = (PCALLBACK_CONTEXT)ExAllocatePoolWithTag(
		PagedPool,
		sizeof(CALLBACK_CONTEXT),
		REGFLTR_POOL_TAG);

	if (CallbackCtx == NULL) {
		ErrorPrint("CreateCallbackContext failed due to insufficient resources.");
		goto Exit;
	}

	RtlZeroMemory(CallbackCtx, sizeof(CALLBACK_CONTEXT));

	CallbackCtx->CallbackMode = CallbackMode;
	CallbackCtx->ProcessId = IoGetCurrentProcess();

	Status = RtlStringCbPrintfW(CallbackCtx->AltitudeBuffer,
		MAX_ALTITUDE_BUFFER_LENGTH * sizeof(WCHAR),
		L"%s",
		AltitudeString);

	if (!NT_SUCCESS(Status)) {
		ErrorPrint("RtlStringCbPrintfW in CreateCallbackContext failed. Status 0x%x", Status);
		goto Exit;
	}

	RtlInitUnicodeString(&CallbackCtx->Altitude, CallbackCtx->AltitudeBuffer);

	Success = TRUE;

Exit:

	if (Success == FALSE) {
		if (CallbackCtx != NULL) {
			ExFreePoolWithTag(CallbackCtx, REGFLTR_POOL_TAG);
			CallbackCtx = NULL;
		}
	}

	return CallbackCtx;

}

BOOLEAN InsertCallbackContext(IN PCALLBACK_CONTEXT CallbackCtx)
{

	BOOLEAN Success = FALSE;

	ExAcquireFastMutex(&g_CallbackCtxListLock);

	if (g_NumCallbackCtxListEntries < MAX_CALLBACK_CTX_ENTRIES) {
		g_NumCallbackCtxListEntries++;
		InsertHeadList(&g_CallbackCtxListHead, &CallbackCtx->CallbackCtxList);
		Success = TRUE;
	}
	else {
		ErrorPrint("Insert Callback Ctx failed: Max CallbackCtx entries reached.");
	}

	ExReleaseFastMutex(&g_CallbackCtxListLock);

	return Success;

}

PCALLBACK_CONTEXT FindCallbackContext(IN LARGE_INTEGER Cookie)
{

	PCALLBACK_CONTEXT CallbackCtx = NULL;
	PLIST_ENTRY Entry;

	ExAcquireFastMutex(&g_CallbackCtxListLock);

	Entry = g_CallbackCtxListHead.Flink;
	while (Entry != &g_CallbackCtxListHead) {

		CallbackCtx = CONTAINING_RECORD(Entry,
			CALLBACK_CONTEXT,
			CallbackCtxList);
		if (CallbackCtx->Cookie.QuadPart == Cookie.QuadPart) {
			break;
		}

		Entry = Entry->Flink;
	}

	ExReleaseFastMutex(&g_CallbackCtxListLock);

	if (CallbackCtx == NULL) {
		ErrorPrint("FindCallbackContext failed: No context with specified cookied was found.");
	}

	return CallbackCtx;

}

PCALLBACK_CONTEXT FindAndRemoveCallbackContext(IN LARGE_INTEGER Cookie)
{

	PCALLBACK_CONTEXT CallbackCtx = NULL;
	PLIST_ENTRY Entry;

	ExAcquireFastMutex(&g_CallbackCtxListLock);

	Entry = g_CallbackCtxListHead.Flink;
	while (Entry != &g_CallbackCtxListHead) {

		CallbackCtx = CONTAINING_RECORD(Entry,
			CALLBACK_CONTEXT,
			CallbackCtxList);
		if (CallbackCtx->Cookie.QuadPart == Cookie.QuadPart) {
			RemoveEntryList(&CallbackCtx->CallbackCtxList);
			g_NumCallbackCtxListEntries--;
			break;
		}
	}

	ExReleaseFastMutex(&g_CallbackCtxListLock);

	if (CallbackCtx == NULL) {
		ErrorPrint("FindAndRemoveCallbackContext failed: No context with specified cookied was found.");
	}

	return CallbackCtx;
}


VOID DeleteCallbackContext(IN PCALLBACK_CONTEXT CallbackCtx)
{

	if (CallbackCtx != NULL) {
		ExFreePoolWithTag(CallbackCtx, REGFLTR_POOL_TAG);
	}
}

NTSTATUS
CallbackPreNotificationBlock(
	_In_ PCALLBACK_CONTEXT CallbackCtx,
	_In_ REG_NOTIFY_CLASS NotifyClass,
	_Inout_ PVOID Argument2
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING AbsName = RTL_CONSTANT_STRING(ROOT_KEY_ABS_PATH);
	POBJECT_NAME_INFORMATION NameInfo = NULL;

	switch (NotifyClass) {
	case RegNtPreDeleteValueKey: {
		PREG_DELETE_VALUE_KEY_INFORMATION PreDeleteInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreDeleteInfo->Object, NULL)) {
			Status = STATUS_ACCESS_DENIED;
		}
		if (CheckObjectAndPolicy(CallbackCtx, PreDeleteInfo->Object, PreDeleteInfo->ValueName)) {
			Status = STATUS_ACCESS_DENIED;
		}
		if (CheckObjectAndPolicy(CallbackCtx, NULL, PreDeleteInfo->ValueName)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreDeleteKey: {
		PREG_DELETE_KEY_INFORMATION PreDeleteKey = (PREG_DELETE_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreDeleteKey->Object, NULL)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreOpenKey:
	case RegNtPreCreateKey: {
		PREG_PRE_CREATE_KEY_INFORMATION PreCreateInfo = (PREG_PRE_CREATE_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, NULL, PreCreateInfo->CompleteName)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreOpenKeyEx:
	case RegNtPreCreateKeyEx: {
		PREG_CREATE_KEY_INFORMATION PreCreateInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreCreateInfo->RootObject, PreCreateInfo->CompleteName)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}

	case RegNtPreSetValueKey: {
		PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreSetValueInfo->Object, PreSetValueInfo->ValueName)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreRenameKey: {
		PREG_RENAME_KEY_INFORMATION PreRenameKey = (PREG_RENAME_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreRenameKey->Object, NULL)) {
			Status = STATUS_ACCESS_DENIED;
		}
		if (CheckObjectAndPolicy(CallbackCtx, NULL, PreRenameKey->NewName)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreReplaceKey: {
		PREG_REPLACE_KEY_INFORMATION PreReplaceKey = (PREG_REPLACE_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreReplaceKey->Object, NULL)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreSetInformationKey: {
		PREG_SET_INFORMATION_KEY_INFORMATION PreSetInformationKey = (PREG_SET_INFORMATION_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreSetInformationKey->Object, NULL)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreUnLoadKey: {
		PREG_UNLOAD_KEY_INFORMATION PreUnloadKey = (PREG_UNLOAD_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreUnloadKey->Object, NULL)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreSetKeySecurity: {
		PREG_SET_KEY_SECURITY_INFORMATION PreSetKeySecurity = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreSetKeySecurity->Object, NULL)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreRestoreKey: {
		PREG_RESTORE_KEY_INFORMATION PreRestoreKey = (PREG_RESTORE_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreRestoreKey->Object, NULL)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreSaveKey: {
		PREG_SAVE_KEY_INFORMATION PreSaveKey = (PREG_SAVE_KEY_INFORMATION)Argument2;
		if (CheckObjectAndPolicy(CallbackCtx, PreSaveKey->Object, NULL)) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}

	default:
		break;
	}


	if (NameInfo)
		ExFreePoolWithTag(NameInfo, REGFLTR_POOL_TAG);

	return Status;
}