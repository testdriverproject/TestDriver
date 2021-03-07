#include <ntifs.h>  //包含头文件
#include <结束进程.h>
#include <保护进程.h>
#include <暂停恢复进程.h>
#include <ForceDelete.h>


#define DEVICE_NAME			L"\\Device\\Test64"   //定义驱动名称
#define LINK_NAME			L"\\DosDevices\\Test64"


#define IOCTL_IO_Test		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) //输出文本
#define IOCTL_IO_Test2		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) //输出整数

#define IOCTL_IO_KillProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) //杀进程
#define IOCTL_IO_ProtectProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) //保护进程
#define IOCTL_IO_OpenProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS) //打开进程

#define IOCTL_IO_DeleteFile			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS) //删除文件
#define IOCTL_IO_LockFile			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS) //锁定文件

#define IOCTL_IO_PauseProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS) //暂停进程
#define IOCTL_IO_ResumeProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS) //恢复进程




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

//驱动控制码
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);  //为了让编译器不必检测你的警告

	NTSTATUS Status = STATUS_SUCCESS;//默认返回成功
	PIO_STACK_LOCATION  IoStackLocation = NULL;
	PVOID InputData = NULL, OutputData = NULL;
	ULONG InputDataLength = 0, OutputDataLength = 0, IoControlCode = 0;

	// 取得此IRP（pIrp）的I/O堆栈指针
	IoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	//控制码
	IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	//输入输出缓冲区
	InputData = pIrp->AssociatedIrp.SystemBuffer;
	OutputData = pIrp->AssociatedIrp.SystemBuffer;
	//输入区域大小
	InputDataLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	//输出区域大小
	OutputDataLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

	//----------------------------------------此处开始判断控制码----------------------------------------------

	switch (IoControlCode)
	{

	case IOCTL_IO_Test:     
	{
		UNICODE_STRING 通信的文本 = { 0 };           //unicode文本型
		RtlInitUnicodeString(&通信的文本, InputData);   //RTL_CONSTANT_STRING返回字符串结构或Unicode字符串结构。
		DbgPrint("通信的文本:%wZ\n", &通信的文本);         //输出文本
		Status = STATUS_SUCCESS;     //返回通信成功
		break;
	}


	case IOCTL_IO_Test2:     
	{;        
		DbgPrint("Number  :   %d\n", *((PVOID*)InputData)); 
		Status = STATUS_SUCCESS;  
		break;
	}

	case IOCTL_IO_KillProcess:
	{
		HANDLE pid = *((PVOID*)InputData);
		DbgPrint("kill pid  :   %d\n", pid);
		ZwKillProcess((HANDLE)pid);
		Status = STATUS_SUCCESS;     //返回通信成功
		break;
	}

	case IOCTL_IO_ProtectProcess:
	{
		HANDLE pid = *((PVOID*)InputData);
		DbgPrint("protect  pid:   %d\n", pid);
		g_protectpid = pid;
		Status = STATUS_SUCCESS;     //返回通信成功
		break;
	}


	case IOCTL_IO_OpenProcess:
	{
		HANDLE pid = *((PVOID*)InputData);
		DbgPrint("open  pid:   %d\n", pid);
		ZwOpenProcess_((HANDLE)pid);
		Status = STATUS_SUCCESS;     //返回通信成功
		break;
	}

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
	case IOCTL_IO_PauseProcess:
	{
		HANDLE pid = *((PVOID*)InputData);
		DbgPrint("Pause  pid:   %d\n", pid);
		PauseProcess(pid);
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_ResumeProcess:
	{
		HANDLE pid = *((PVOID*)InputData);
		DbgPrint("Resume  pid:   %d\n", pid);
		ResumeProcess(pid);
		Status = STATUS_SUCCESS;
		break;

	}


	//----------------------------------------此处结束判断控制码----------------------------------------------


	default:          //如果控制码没有定义就返回 通信失败
		DbgPrint("未定义的控制码 : %d", IoControlCode);
		Status = STATUS_UNSUCCESSFUL;     
		break;
	}

	//设定DeviceIoControl的*lpBytesReturned的值（如果通信失败则返回0长度）
	if (Status == STATUS_SUCCESS)
		if (pIrp->IoStatus.Information = 0)
		pIrp->IoStatus.Information = OutputDataLength;
	else
		pIrp->IoStatus.Information = 0;
	//设定DeviceIoControl的返回值是成功还是失败
	pIrp->IoStatus.Status = Status; //Ring3 GetLastError();
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status; //Ring3 DeviceIoControl()返回值
}

//驱动将被卸载
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING symLinkName;
	//移除回调句柄
	RtlInitUnicodeString(&symLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&symLinkName);
	//删除设备
	IoDeleteDevice(pDriverObj->DeviceObject);
	//移除进程回调
	ObUnRegisterCallbacks(g_pRegiHandle);
	DbgPrint("TestDriver 驱动卸载\n");
}

//驱动入口
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName = { 0 };
	UNICODE_STRING ustrDevName = { 0 };
	PDEVICE_OBJECT pDevObj = NULL;

	OB_OPERATION_REGISTRATION oor;
	OB_CALLBACK_REGISTRATION ob;

	PLDR_DATA_TABLE_ENTRY64 ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;//加载驱动的时候会判断此值。必须有特殊签名才行，增加0x20即可。否则将调用失败   

	//注册回调函数
	oor.ObjectType = PsProcessType;
	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	oor.PreOperation = precessCallBack;
	oor.PostOperation = NULL;

	ob.Version = OB_FLT_REGISTRATION_VERSION;
	ob.OperationRegistrationCount = 1;
	ob.OperationRegistration = &oor;
	RtlInitUnicodeString(&ob.Altitude, L"321000");
	ob.RegistrationContext = NULL;
	ObRegisterCallbacks(&ob, &g_pRegiHandle);

	DbgPrint("TestDiver驱动加载成功 :%S\n", pRegistryString->Buffer);
	DbgPrint("该驱动为开源驱动,部分代码摘自网络. 作者:冰棍好烫啊");
	DbgPrint("驱动源码 / 模块源码 / 问题 + q群 342425202");
	
	//删除驱动文件
//	UNICODE_STRING pusDriverPath = ((PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection)->FullDllName;
//	DbgPrint("DriverPath:%wZ\n", &pusDriverPath);
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
