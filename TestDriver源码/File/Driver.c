#include "ForceDelete.h"
#define DEVICE_NAME			L"\\Device\\FileDriver"
#define LINK_NAME			L"\\DosDevices\\FileDriver"


#define IOCTL_IO_DeleteFile			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) //删除文件
#define IOCTL_IO_LockFile			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) //锁定文件



typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks;
	ULONG64 SectionPointer;
	ULONG64 CheckSum;
	ULONG64 TimeDateStamp;
	ULONG64 LoadedImports;
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	ULONG64 ContextInformation;
	ULONG64 OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;


VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING symLinkName;
	//移除回调句柄
	RtlInitUnicodeString(&symLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&symLinkName);
	//删除设备
	IoDeleteDevice(pDriverObj->DeviceObject);
	//DbgPrint("DriverUnload\n");
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj); 

	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION  IoStackLocation = NULL;
	PVOID InputData = NULL, OutputData = NULL;
	ULONG InputDataLength = 0, OutputDataLength = 0, IoControlCode = 0;  //无符号长整数

	IoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	InputData = pIrp->AssociatedIrp.SystemBuffer;
	OutputData = pIrp->AssociatedIrp.SystemBuffer;
	InputDataLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	OutputDataLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

	switch (IoControlCode)
	{
	case IOCTL_IO_DeleteFile:
	{
		UNICODE_STRING DeleteFilePath = { 0 };
		RtlInitUnicodeString(&DeleteFilePath, InputData);
		ForceDeleteFile(DeleteFilePath);
		DbgPrint("DeleteFilePath:%wZ\n", &DeleteFilePath);
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_LockFile:
	{
		UNICODE_STRING LockFilePath = { 0 };
		RtlInitUnicodeString(&LockFilePath, InputData);
		DbgPrint("LockFilePath:%wZ\n", &LockFilePath);
		ProtectFile(LockFilePath);
		Status = STATUS_SUCCESS;
		break;
	}

	default:
		Status = STATUS_UNSUCCESSFUL;
		break;
	}
	//这里设定DeviceIoControl的*lpBytesReturned的值（如果通信失败则返回0长度）
	if (Status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = OutputDataLength;
	else
		pIrp->IoStatus.Information = 0;
	//这里设定DeviceIoControl的返回值是成功还是失败
	pIrp->IoStatus.Status = Status; //Ring3 GetLastError();
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status; //Ring3 DeviceIoControl()返回值
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName = { 0 };
	UNICODE_STRING ustrDevName = { 0 };
	PDEVICE_OBJECT pDevObj = NULL;

	DbgPrint("DriverEntry:%S\n", pRegistryString->Buffer);
	//删除驱动文件
	UNICODE_STRING pusDriverPath = ((PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection)->FullDllName;
	DbgPrint("DriverPath:%wZ\n", &pusDriverPath);
	//DeleteFile(pusDriverPath);

	//设置分发函数和卸载例程
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME); //将设备名转换为Unicode字符串	
	Status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj); //创建设备对象
	//pDevObj->Flags |= DO_BUFFERED_IO; //创建设备被设定为直接缓冲I/O
	if (!NT_SUCCESS(Status))	return Status;
	RtlInitUnicodeString(&ustrLinkName, LINK_NAME); //将符号名转换为Unicode字符串
	Status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName); //将符号与设备关联
	if (!NT_SUCCESS(Status))
	{
		//DbgPrint("IoCreateSymbolicLink:0x%x\n", Status);
		IoDeleteDevice(pDevObj);
		return Status;
	}
	//DbgPrint("SymbolicLink:%S\n", ustrLinkName.Buffer);
	return Status;
}