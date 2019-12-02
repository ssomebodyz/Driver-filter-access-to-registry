#include "stdlib.h"
#include "stdio.h"
#include <fltKernel.h>
#include "strsafe.h"
#include <wdmsec.h>
#include<wdm.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#pragma warning(disable:4047)
#pragma warning(disable:4133)
#pragma warning(disable:4189)
#pragma warning(disable:4055)
#pragma warning(disable:4267)
#pragma warning(disable:4098)
#pragma warning(disable:4101)
#pragma warning(disable:4131)
#pragma warning(disable:4210)
#pragma warning(disable:4702)
#define DRIVER_NAME             L"RegFltr"
#define DRIVER_NAME_WITH_EXT    L"RegFltr.sys"
#define NT_DEVICE_NAME          L"\\Device\\RegFltr"
#define DOS_DEVICES_LINK_NAME   L"\\DosDevices\\RegFltr"
#define WIN32_DEVICE_NAME       L"\\\\.\\RegFltr"
#define DEVICE_SDDL             L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
int flag = 0;
extern UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);

char* GetProcessNameFromPid(HANDLE pid)
{
	PEPROCESS Process;
	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
	{
		return "pid???";
	}
	return (CHAR*)PsGetProcessImageFileName(Process);
}
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DeviceUnload;
NTSTATUS RfPreOpenKeyEx(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PREG_CREATE_KEY_INFORMATION CallbackData);
typedef NTSTATUS(*QUERY_INFO_PROCESS)
(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

QUERY_INFO_PROCESS ZwQueryInformationProcess;
PEX_CALLBACK_FUNCTION g_RegistryCallbackTable[MaxRegNtNotifyClass];
#define PR_LENGHT 128

_Dispatch_type_(IRP_MJ_CREATE)         DRIVER_DISPATCH DeviceCreate;
_Dispatch_type_(IRP_MJ_CLOSE)          DRIVER_DISPATCH DeviceClose;
_Dispatch_type_(IRP_MJ_CLEANUP)        DRIVER_DISPATCH DeviceCleanup;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DeviceControl;

struct
{
	char process[PR_LENGHT];
	char info[PR_LENGHT];

}info[10];


LIST_ENTRY g_CallbackCtxListHead;
FAST_MUTEX g_CallbackCtxListLock;
USHORT g_NumCallbackCtxListEntries;
PDEVICE_OBJECT g_DeviceObj;
ULONG g_MajorVersion;
ULONG g_MinorVersion;
BOOLEAN g_RMCreated;
int num_process;
int num_proc;
char* rules;
LARGE_INTEGER g_cookie;
int notification;

typedef struct _RMCALLBACK_CONTEXT
{
	ULONG Notification;
	HANDLE Enlistment;

} RMCALLBACK_CONTEXT, *PRMCALLBACK_CONTEXT;
PRMCALLBACK_CONTEXT RMCallbackCtx;

NTSTATUS GetProcessImageName(HANDLE processId, PUNICODE_STRING ProcessImageName)
{
	NTSTATUS status;
	ULONG returnedLength;
	ULONG bufferLength;
	HANDLE hProcess = NULL;
	PVOID buffer;
	PEPROCESS eProcess;
	PUNICODE_STRING imageName;
	PAGED_CODE();
	status = PsLookupProcessByProcessId(processId, &eProcess);
	if (NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcess);
		if (NT_SUCCESS(status))
		{
		}
		else
		{

			DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
		}
		ObDereferenceObject(eProcess);
	}
	else 
	{

		DbgPrint("PsLookupProcessByProcessId Failed: %08x\n", status);
	}
	if (NULL == ZwQueryInformationProcess)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
		if (NULL == ZwQueryInformationProcess)
		{
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
		}
	}
	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &returnedLength);
	if (STATUS_INFO_LENGTH_MISMATCH != status)
	{
		return status;
	}
	bufferLength = returnedLength - sizeof(UNICODE_STRING);
	if (ProcessImageName->MaximumLength < bufferLength)
	{
		ProcessImageName->MaximumLength = (USHORT)bufferLength;
		return STATUS_BUFFER_OVERFLOW;
	}
	buffer = ExAllocatePoolWithTag(NonPagedPool, returnedLength, 'uLT1');
	if (NULL == buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, buffer, returnedLength, &returnedLength);

	if (NT_SUCCESS(status))
	{
		imageName = (PUNICODE_STRING)buffer;
		RtlCopyUnicodeString(ProcessImageName, imageName);
	}
	ExFreePoolWithTag(buffer, 'uLT1');
	return status;
}
int thread_count = 0;
HANDLE  fileHandle;
HANDLE fileHandles[100];
IO_STATUS_BLOCK   iostatus;
OBJECT_ATTRIBUTES oa;
UNICODE_STRING    fullFileName;
void createHandle()
{
	RtlInitUnicodeString(&fullFileName, L"\\??\\C:\\Users\\somebody\\Desktop\\info.txt");
	InitializeObjectAttributes(&oa, &fullFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ZwCreateFile(&fileHandle, GENERIC_WRITE | SYNCHRONIZE, &oa, &iostatus, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	FILE_STANDARD_INFORMATION fileInfo;
	ZwQueryInformationFile(fileHandle, &iostatus, &fileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
}

void PcreateThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId,BOOLEAN Create)
{

		DbgPrint("Thread is coming...");
		NTSTATUS          status;
		LARGE_INTEGER systemTime;
		LARGE_INTEGER localTime;
		TIME_FIELDS   timeFields;
		KeQuerySystemTime(&systemTime);
		UNREFERENCED_PARAMETER(ThreadId);
		ExSystemTimeToLocalTime(&systemTime, &localTime);
		RtlTimeToTimeFields(&localTime, &timeFields);
		char tmp[100];
		char proc[1024];
		char created[] = "Thread Created";
		char returned[] = "Thread Closed";
		char total_string[] = { 0 };
		if (Create)
		{
			strcpy(total_string, created);
          
		}
		else if (!Create)
		{
			strcpy(total_string, returned);
		}
		RtlStringCbPrintfA(tmp, sizeof(tmp), " %2.2d:%2.2d:%2.2d %d :", timeFields.Hour, timeFields.Minute,timeFields.Second, timeFields.Year);
		RtlStringCbPrintfA(proc, sizeof(proc), " Process name: %s ,Process PID: %u ,%s with PID : %u\n",GetProcessNameFromPid(ProcessId),ProcessId, total_string,ThreadId);
		thread_count++;
		{
			strcat(tmp, proc);
			if (Create || !Create)
			{
				ULONG len = strlen(tmp);
				if (Create || !Create)
				{
				    status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, tmp, len, NULL, NULL);
					DbgPrint("Log writed!\n");
					if (!NT_SUCCESS(status) || iostatus.Information != len)
					{
						DbgPrint("Error on writing. Status = %x.", status);
					}
				}
			}
		}

}
NTSTATUS RfPreOpenKeyEx(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PREG_OPEN_KEY_INFORMATION CallbackData)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
	PUNICODE_STRING pKeyNameBeingOpened = CallbackData->CompleteName;
	char path[1024];
	NTSTATUS RtlPrint = RtlStringCbPrintfA(path, sizeof(path), "%wZ", pKeyNameBeingOpened);
	if (RtlPrint != STATUS_SUCCESS)
	{
		DbgPrint("RtlStringCbPrintfA returned unexpected error status 0x%x.", RtlPrint);
		return STATUS_SUCCESS;
	}
	for (int r = 0; r < num_process; r++)
	{
		DbgPrint("Finding path..\n");
		DbgPrint("Path %s\n", path);
		DbgPrint("Proc name %s\n", info[r].process);
		if (!strcmp(path, info[r].process))
		{
			DbgPrint("Checking permissions..\n");
			if ((!strcmp(info[num_proc].info, "lowlevel") && (!strcmp(info[r].info, "mediumlevel") || !strcmp(info[r].info, "highlevel")))
				|| (!strcmp(info[num_proc].info, "mediumlevel") && (!strcmp(info[r].info, "highlevel"))) || (!strcmp(info[r].info, "system")))

			{
				DbgPrint("Access for %wZ being denied!\n", pKeyNameBeingOpened);
				return STATUS_ACCESS_DENIED;
			}
			else
			{
				DbgPrint("Access for %wZ being alloweed!\n", pKeyNameBeingOpened);
				return STATUS_SUCCESS;
			}
		}
	}

	return STATUS_SUCCESS;
}
NTSTATUS RfRegistryCallback(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	HANDLE hProcess = PsGetCurrentProcessId();
	REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	if (Argument2 == NULL)
	{
		DbgPrint("\tCallback: Argument 2 unexpectedly 0. Filter will abort and return success.");
		return STATUS_SUCCESS;
	}
	UNICODE_STRING fullPath;
	char ProcessName[1024];
	fullPath.Length = 0;
	fullPath.MaximumLength = 520;
	fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, 520, 'uUT1');
	GetProcessImageName(hProcess, &fullPath);
	RtlStringCbPrintfA(ProcessName, sizeof(ProcessName), "%S", fullPath.Buffer);
	for (int r = 0; r < num_process; r++)
	{
		if (strstr(ProcessName, info[r].process) != NULL)
		{
			DbgPrint("Process found!");
			DbgPrint("%s", ProcessName);
			num_proc = r;
			ExFreePoolWithTag(fullPath.Buffer, 'uUT1');
			if (!g_RegistryCallbackTable[Operation])
			{
				return STATUS_SUCCESS;
			}
			return g_RegistryCallbackTable[Operation](CallbackContext, Argument1, Argument2);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS ParseData(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IrpStack;
	ULONG OutputBufferLength;
	char buffer[256];
	UNREFERENCED_PARAMETER(DeviceObject);
	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	rules = (char*)Irp->AssociatedIrp.SystemBuffer;
	DbgPrint("Rules: %s ", rules);
	int i = 0, j = 0, h = 0;
	rules[strlen(rules)] = '*';
	int proc_number = 0;
	int reg_number = 0;
	int k = 0;
	while (1)
	{
		
			while (rules[j] != '"') { if (rules[j] == '*') { proc_number++; goto end; }; j++; } j++; k = 0;
			while (rules[j] != '"') { if (rules[j] == '*') { proc_number++; goto end; }; info[proc_number].process[k] = rules[j]; j++; k++; } j++;
			while (rules[j] != '"') { if (rules[j] == '*') { proc_number++; goto end; }; j++; } j++; k = 0;
			while (rules[j] != '"') { if (rules[j] == '*') { proc_number++; goto end; }; info[proc_number].info[k] = rules[j]; j++; k++; }j++;
		
		if (rules[j] == '*') { proc_number++; goto end; }
		j++;
		proc_number++;
	}
	proc_number++;
end:
	proc_number++;
	num_process = proc_number;
	DbgPrint("Total procs: %d\n", num_process);
	if (OutputBufferLength < sizeof(buffer))

	{
		Status = STATUS_INVALID_PARAMETER;
	}
	Irp->IoStatus.Information = sizeof(buffer);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("FromApp failed. Status 0x%x", Status);
	}
	else 
	{
		DbgPrint("FromAppSucced");
	}
	return Status;
}

NTSTATUS NotificateChange(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IrpStack;
	ULONG OutputBufferLength;
	char buffer[2];
	char *buf;
	UNREFERENCED_PARAMETER(DeviceObject);
	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	buf = (char*)Irp->AssociatedIrp.SystemBuffer;
	DbgPrint("%s", buf);
	if (buf[0] == '1' && notification == 0)
	{
		notification = 1;
		createHandle();
		NTSTATUS ntStatus = PsSetCreateThreadNotifyRoutine(PcreateThreadNotifyRoutine);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("noticitaroe error status 0x%x.", ntStatus);
		}
		else
		{
			DbgPrint("notificator  set.\n");
		}
	}
	else if (buf[0] == '2' && notification == 1)
	{
		DbgPrint("Closing handle...");
		ZwClose(fileHandle);
		notification = 0;
		NTSTATUS remove = PsRemoveCreateThreadNotifyRoutine(PcreateThreadNotifyRoutine);
		if (!NT_SUCCESS(remove))
		{
			DbgPrint("error status 0x%x.", remove);
		}
		else 
		{
			DbgPrint("notificator  removed\n");
		}
	}
	if (OutputBufferLength < sizeof(buffer)) 
	{
		goto Exit;
		Status = STATUS_INVALID_PARAMETER;
	}
	Irp->IoStatus.Information = sizeof(buffer);
	Exit:
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("FromApp failed. Status 0x%x", Status);
	}
	else 
	{
		DbgPrint("FromAppSucced");
	}

	return Status;
}
VOID DeviceUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING  DosDevicesLinkName;
	UNREFERENCED_PARAMETER(DriverObject);
	PAGED_CODE();
	NTSTATUS status = CmUnRegisterCallback(g_cookie);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("CmUnRegisterCallback returned unexpected error status 0x%x.", status);
	}

	if (notification == 1)
	{
		NTSTATUS remove = PsRemoveCreateThreadNotifyRoutine(PcreateThreadNotifyRoutine);
		if (!NT_SUCCESS(remove))
		{
			DbgPrint("PsRemoveLoadImageNotifyRoutine returned unexpected error status 0x%x.", remove);
		}
		else
		{
			DbgPrint("PsRemoveLoadImageNotifyRoutine: notification remove.\n");
		}
	}
	RtlInitUnicodeString(&DosDevicesLinkName, DOS_DEVICES_LINK_NAME);
	IoDeleteSymbolicLink(&DosDevicesLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "RegFltr: DeviceUnload\n");
}
NTSTATUS DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DeviceCleanup(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	PIO_STACK_LOCATION IrpStack;
	ULONG Ioctl;
	NTSTATUS Status;
	UNREFERENCED_PARAMETER(DeviceObject);
	Status = STATUS_SUCCESS;
	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
	if (ControlCode == 0x801)
	{
		DbgPrint("Starting copy rules..\n");
		Status = ParseData(DeviceObject, Irp);
	}
	else if (ControlCode == 0x802)
	{
		DbgPrint("Setting notifier....\n");
		Status =NotificateChange(DeviceObject, Irp);
	}
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status;
	UNICODE_STRING NtDeviceName;
	UNICODE_STRING DosDevicesLinkName;
	UNICODE_STRING DeviceSDDLString;
	UNREFERENCED_PARAMETER(RegistryPath);
	notification = 0;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "RegFltr: DriverEntry()\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "RegFltr: Use ed nt!Kd_IHVDRIVER_Mask 8 to enable more detailed printouts\n");
	RtlInitUnicodeString(&NtDeviceName, NT_DEVICE_NAME);
	RtlInitUnicodeString(&DeviceSDDLString, DEVICE_SDDL);
	DbgPrint("Start working..1\n");
	Status = IoCreateDevice(DriverObject, 0, &NtDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObj);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Error create device\n");
		return Status;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DeviceCleanup;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = DeviceUnload;
	DbgPrint("Start working..2\n");
	RtlInitUnicodeString(&DosDevicesLinkName, DOS_DEVICES_LINK_NAME);
	Status = IoCreateSymbolicLink(&DosDevicesLinkName, &NtDeviceName);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Error create link..2\n");
		IoDeleteDevice(DriverObject->DeviceObject);
		return Status;
	}
	CmGetCallbackVersion(&g_MajorVersion, &g_MinorVersion);
	DbgPrint("Callback version %u.%u", g_MajorVersion, g_MinorVersion);
	g_RegistryCallbackTable[RegNtPreOpenKeyEx] = (PEX_CALLBACK_FUNCTION)RfPreOpenKeyEx;
	g_RegistryCallbackTable[RegNtPreDeleteKey] = (PEX_CALLBACK_FUNCTION)RfPreOpenKeyEx;
	g_RegistryCallbackTable[RegNtPreRenameKey] = (PEX_CALLBACK_FUNCTION)RfPreOpenKeyEx;
	g_RegistryCallbackTable[RegNtPreCreateKey] = (PEX_CALLBACK_FUNCTION)RfPreOpenKeyEx;
	UNICODE_STRING AltitudeString = RTL_CONSTANT_STRING(L"380000");
	NTSTATUS status = CmRegisterCallbackEx(RfRegistryCallback, &AltitudeString, DriverObject, NULL, &g_cookie, NULL);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("CmRegisterCallbackEx returned unexpected error status 0x%x.", status);
	}
	if (NT_SUCCESS(Status))
	{
		g_RMCreated = TRUE;
	}
	InitializeListHead(&g_CallbackCtxListHead);
	ExInitializeFastMutex(&g_CallbackCtxListLock);
	g_NumCallbackCtxListEntries = 0;
	return STATUS_SUCCESS;
}