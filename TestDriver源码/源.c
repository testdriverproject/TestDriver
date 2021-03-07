#include <ntifs.h>  //����ͷ�ļ�
#include <��������.h>
#include <��������.h>
#include <��ͣ�ָ�����.h>
#include <ForceDelete.h>


#define DEVICE_NAME			L"\\Device\\Test64"   //������������
#define LINK_NAME			L"\\DosDevices\\Test64"


#define IOCTL_IO_Test		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) //����ı�
#define IOCTL_IO_Test2		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) //�������

#define IOCTL_IO_KillProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) //ɱ����
#define IOCTL_IO_ProtectProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) //��������
#define IOCTL_IO_OpenProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS) //�򿪽���

#define IOCTL_IO_DeleteFile			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS) //ɾ���ļ�
#define IOCTL_IO_LockFile			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS) //�����ļ�

#define IOCTL_IO_PauseProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS) //��ͣ����
#define IOCTL_IO_ResumeProcess		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS) //�ָ�����




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

//����������
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);  //Ϊ���ñ��������ؼ����ľ���

	NTSTATUS Status = STATUS_SUCCESS;//Ĭ�Ϸ��سɹ�
	PIO_STACK_LOCATION  IoStackLocation = NULL;
	PVOID InputData = NULL, OutputData = NULL;
	ULONG InputDataLength = 0, OutputDataLength = 0, IoControlCode = 0;

	// ȡ�ô�IRP��pIrp����I/O��ջָ��
	IoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	//������
	IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	//�������������
	InputData = pIrp->AssociatedIrp.SystemBuffer;
	OutputData = pIrp->AssociatedIrp.SystemBuffer;
	//���������С
	InputDataLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	//��������С
	OutputDataLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

	//----------------------------------------�˴���ʼ�жϿ�����----------------------------------------------

	switch (IoControlCode)
	{

	case IOCTL_IO_Test:     
	{
		UNICODE_STRING ͨ�ŵ��ı� = { 0 };           //unicode�ı���
		RtlInitUnicodeString(&ͨ�ŵ��ı�, InputData);   //RTL_CONSTANT_STRING�����ַ����ṹ��Unicode�ַ����ṹ��
		DbgPrint("ͨ�ŵ��ı�:%wZ\n", &ͨ�ŵ��ı�);         //����ı�
		Status = STATUS_SUCCESS;     //����ͨ�ųɹ�
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
		Status = STATUS_SUCCESS;     //����ͨ�ųɹ�
		break;
	}

	case IOCTL_IO_ProtectProcess:
	{
		HANDLE pid = *((PVOID*)InputData);
		DbgPrint("protect  pid:   %d\n", pid);
		g_protectpid = pid;
		Status = STATUS_SUCCESS;     //����ͨ�ųɹ�
		break;
	}


	case IOCTL_IO_OpenProcess:
	{
		HANDLE pid = *((PVOID*)InputData);
		DbgPrint("open  pid:   %d\n", pid);
		ZwOpenProcess_((HANDLE)pid);
		Status = STATUS_SUCCESS;     //����ͨ�ųɹ�
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


	//----------------------------------------�˴������жϿ�����----------------------------------------------


	default:          //���������û�ж���ͷ��� ͨ��ʧ��
		DbgPrint("δ����Ŀ����� : %d", IoControlCode);
		Status = STATUS_UNSUCCESSFUL;     
		break;
	}

	//�趨DeviceIoControl��*lpBytesReturned��ֵ�����ͨ��ʧ���򷵻�0���ȣ�
	if (Status == STATUS_SUCCESS)
		if (pIrp->IoStatus.Information = 0)
		pIrp->IoStatus.Information = OutputDataLength;
	else
		pIrp->IoStatus.Information = 0;
	//�趨DeviceIoControl�ķ���ֵ�ǳɹ�����ʧ��
	pIrp->IoStatus.Status = Status; //Ring3 GetLastError();
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status; //Ring3 DeviceIoControl()����ֵ
}

//��������ж��
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING symLinkName;
	//�Ƴ��ص����
	RtlInitUnicodeString(&symLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&symLinkName);
	//ɾ���豸
	IoDeleteDevice(pDriverObj->DeviceObject);
	//�Ƴ����̻ص�
	ObUnRegisterCallbacks(g_pRegiHandle);
	DbgPrint("TestDriver ����ж��\n");
}

//�������
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
	ldr->Flags |= 0x20;//����������ʱ����жϴ�ֵ������������ǩ�����У�����0x20���ɡ����򽫵���ʧ��   

	//ע��ص�����
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

	DbgPrint("TestDiver�������سɹ� :%S\n", pRegistryString->Buffer);
	DbgPrint("������Ϊ��Դ����,���ִ���ժ������. ����:�������̰�");
	DbgPrint("����Դ�� / ģ��Դ�� / ���� + qȺ 342425202");
	
	//ɾ�������ļ�
//	UNICODE_STRING pusDriverPath = ((PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection)->FullDllName;
//	DbgPrint("DriverPath:%wZ\n", &pusDriverPath);
	//DeleteFile(pusDriverPath);

	//���÷ַ�������ж������
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME); //���豸��ת��ΪUnicode�ַ���	
	Status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj); //�����豸����
	//pDevObj->Flags |= DO_BUFFERED_IO; //�����豸���趨Ϊֱ�ӻ���I/O
	if (!NT_SUCCESS(Status))	return Status;
	RtlInitUnicodeString(&ustrLinkName, LINK_NAME); //��������ת��ΪUnicode�ַ���
	Status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName); //���������豸����
	if (!NT_SUCCESS(Status))
	{
		//DbgPrint("IoCreateSymbolicLink:0x%x\n", Status);
		IoDeleteDevice(pDevObj);
		return Status;
	}
	//DbgPrint("SymbolicLink:%S\n", ustrLinkName.Buffer);
	return Status;
}
