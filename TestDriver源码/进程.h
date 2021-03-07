#pragma once
extern UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process); //未公开的进行导出即可

PEPROCESS LookupProcess(HANDLE Pid)//pid获取EProcess
{
	PEPROCESS eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess)))
		return eprocess;
	else
		return NULL;
}

char* GetProcessImageNameByProcessID(ULONG ulProcessID)//pid获取进程名
{
	NTSTATUS  Status;
	PEPROCESS  EProcess = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ulProcessID, &EProcess);    //EPROCESS
	//通过句柄获取EProcess
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	ObDereferenceObject(EProcess);
	//通过EProcess获得进程名称
	return (char*)PsGetProcessImageFileName(EProcess);
}

HANDLE ZwOpenProcess_(HANDLE pid)//强力打开进程
{
	HANDLE hProcess = NULL;
	CLIENT_ID ClientId;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS status;
	//填充 CID
	ClientId.UniqueProcess = pid;
	ClientId.UniqueThread = 0;
	//填充 OA
	oa.Length = sizeof(oa);
	oa.RootDirectory = 0;
	oa.ObjectName = 0;
	oa.Attributes = 0;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;
	//打开进程，如果句柄有效，则返回
	status = ZwOpenProcess(&hProcess, 1, &oa, &ClientId);
	if (NT_SUCCESS(status))
	{
		DbgPrint("[打开进程]OpenProcess成功,进程ID: %d", hProcess);

		return hProcess;
	};
	DbgPrint("[打开进程]OpenProcess失败,进程ID: %d", hProcess);
	return hProcess;
}