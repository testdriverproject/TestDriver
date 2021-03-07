#pragma once
extern UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process); //δ�����Ľ��е�������

PEPROCESS LookupProcess(HANDLE Pid)//pid��ȡEProcess
{
	PEPROCESS eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess)))
		return eprocess;
	else
		return NULL;
}

char* GetProcessImageNameByProcessID(ULONG ulProcessID)//pid��ȡ������
{
	NTSTATUS  Status;
	PEPROCESS  EProcess = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ulProcessID, &EProcess);    //EPROCESS
	//ͨ�������ȡEProcess
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	ObDereferenceObject(EProcess);
	//ͨ��EProcess��ý�������
	return (char*)PsGetProcessImageFileName(EProcess);
}

HANDLE ZwOpenProcess_(HANDLE pid)//ǿ���򿪽���
{
	HANDLE hProcess = NULL;
	CLIENT_ID ClientId;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS status;
	//��� CID
	ClientId.UniqueProcess = pid;
	ClientId.UniqueThread = 0;
	//��� OA
	oa.Length = sizeof(oa);
	oa.RootDirectory = 0;
	oa.ObjectName = 0;
	oa.Attributes = 0;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;
	//�򿪽��̣���������Ч���򷵻�
	status = ZwOpenProcess(&hProcess, 1, &oa, &ClientId);
	if (NT_SUCCESS(status))
	{
		DbgPrint("[�򿪽���]OpenProcess�ɹ�,����ID: %d", hProcess);

		return hProcess;
	};
	DbgPrint("[�򿪽���]OpenProcessʧ��,����ID: %d", hProcess);
	return hProcess;
}