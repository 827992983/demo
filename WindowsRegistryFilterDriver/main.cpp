////By Fanxiushu 2011-10-22

#include "ioctl.h"
#include <wdmsec.h>

PDEVICE_OBJECT g_DeviceObj;

static NTSTATUS AddDevice(
	IN  PDRIVER_OBJECT          DriverObject,
	IN  PDEVICE_OBJECT          PhysicalDeviceObject);


static void DeviceUnload(PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING  DosDevicesLinkName = RTL_CONSTANT_STRING(DOS_DEVICES_LINK_NAME);

	IoDeleteSymbolicLink(&DosDevicesLinkName);

	IoDeleteDevice(DriverObject->DeviceObject);

}

NTSTATUS DeviceDispatch(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

extern "C"
NTSTATUS DriverEntry(IN  PDRIVER_OBJECT  DriverObject,
	IN  PUNICODE_STRING    RegistryPathName)
{
	NTSTATUS Status;
	UNICODE_STRING NtDeviceName = RTL_CONSTANT_STRING(NT_DEVICE_NAME);
	UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING(DOS_DEVICES_LINK_NAME);
	UNICODE_STRING DeviceSDDLString = RTL_CONSTANT_STRING(DEVICE_SDDL);
	UNICODE_STRING KeyPath = RTL_CONSTANT_STRING(ROOT_KEY_ABS_PATH);
	OBJECT_ATTRIBUTES FileAttributes;
	UNICODE_STRING Filename;
	HANDLE hFile;
	FILE_STANDARD_INFORMATION FileStandard;
	IO_STATUS_BLOCK IoStatusBlock;
	UNREFERENCED_PARAMETER(RegistryPathName);

	Status = IoCreateDeviceSecure(
		DriverObject,                 // pointer to driver object
		0,                            // device extension size
		&NtDeviceName,                // device name
		FILE_DEVICE_UNKNOWN,          // device type
		0,                            // device characteristics
		TRUE,                         // not exclusive
		&DeviceSDDLString,            // SDDL string specifying access
		NULL,                         // device class guid
		&g_DeviceObj);                // returned device object pointer

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = IoCreateSymbolicLink(&DosDevicesLinkName, &NtDeviceName);

	if (!NT_SUCCESS(Status)) {
		IoDeleteDevice(DriverObject->DeviceObject);
		return Status;
	}

	DriverObject->DriverExtension->AddDevice = AddDevice;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DeviceDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = DeviceUnload;

	InitializeListHead(&g_CallbackCtxListHead);
	ExInitializeFastMutex(&g_CallbackCtxListLock);



	RtlInitUnicodeString(&Filename, L"\\??\\C:\\Windows\\Temp\\QingCloud\\conf\\registery.conf");//初始化文件名  
	memset(&FileAttributes, 0, sizeof(OBJECT_ATTRIBUTES));//对象属性清空  
	InitializeObjectAttributes(&FileAttributes, &Filename, OBJ_CASE_INSENSITIVE, NULL, NULL);//对象属性关键是文件名字 不区分大小写  
	Status = ZwOpenFile(&hFile, GENERIC_ALL, &FileAttributes, &IoStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE); //FILE_NON_DIRECTORY_FILE  FILE_SYNCHRONOUS_IO_NONALERT  
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("ZwOpenFile failed打开文件失败\n"));
	}
	else {
		/*Status = ZwQueryInformationFile(hFile, &IoStatusBlock, &FileStandard, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		DWORD size = FileStandard.EndOfFile.u.LowPart;
		if (NT_SUCCESS(Status))
		{
			CHAR* string;
			string = (CHAR*)ExAllocatePool(NonPagedPool, size);
			LARGE_INTEGER start;
			start.QuadPart = 0;
			Status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, string, size, &start, NULL);
			if (NT_SUCCESS(Status)) {
				int i, j;
				j = 0;
				for (i = 0; i < size; i++) {
					if (string[i] == '\n') {
						HKEY_CLASSES_ROOT
							HKEY_CURRENT_CONFIG
							HKEY_CURRENT_USER
							HKEY_USERS
							HKEY_LOCAL_MACHINE
					}
				}
			}
		}*/
		ZwClose(hFile);

	}

	return STATUS_SUCCESS;
}

static NTSTATUS AddDevice(
	IN  PDRIVER_OBJECT          DriverObject,
	IN  PDEVICE_OBJECT          PhysicalDeviceObject)
{
#pragma warning(disable:28152)
	return STATUS_SUCCESS;
}


