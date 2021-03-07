#pragma once

#include <进程.h>



NTSTATUS ZwKillProcess(HANDLE pid)//强力杀进程
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
	//打开进程，如果句柄有效，则结束进程
	status = ZwOpenProcess(&hProcess, 1, &oa, &ClientId);
	if (NT_SUCCESS(status))
	{
		DbgPrint("[结束进程]OpenProcess成功,进程ID: %d", hProcess);
		ZwTerminateProcess(hProcess, 0);
		ZwClose(hProcess);
		return status;
	};
	DbgPrint("[结束进程]OpenProcess失败,进程ID: %d", hProcess);
	return FALSE;
}

NTSTATUS ZwKillProcessByhProcess(HANDLE hProcess)//强力杀进程
{

	if (hProcess)
	{
		DbgPrint("[结束进程]传入成功,进程ID: %d", hProcess);
		ZwTerminateProcess(hProcess, 0);
		ZwClose(hProcess);
		return STATUS_SUCCESS;
	};
	DbgPrint("[结束进程]传入失败,进程ID: %d", hProcess);
	return FALSE;
}

/*
//暴力清0
void TerminateProcess0(HANDLE Pid)
{
	NTSTATUS status;
	PEPROCESS Process;
	ULONG64  Address;

	status = PsLookupProcessByProcessId(Pid, &Process);
	if (NT_SUCCESS(status))
	{
		KeAttachProcess(Process);
		for (Address = 0; Address <= 0x80000000; Address += PAGE_SIZE)
		{
			_try
			{
				memset(Address, 0, PAGE_SIZE);

			}
				_except(0)
			{
				;

			}

		}

		ObDereferenceObject(Process);

	}
}

//内存清零法结束进程
/*
NTKERNELAPI VOID NTAPI KeAttachProcess(PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeDetachProcess();
//内存清零法结束进程
void PVASE()
{
	SIZE_T i = 0;
	//依附进程
	KeAttachProcess((PEPROCESS)0xFFFFFA8003ABDB30); //这里改为指定进程的 EPROCESS
	for (i = 0x10000; i < 0x20000000; i += PAGE_SIZE)
	{
		__try
		{
			memset((PVOID)i, 0, PAGE_SIZE); //把进程内存全部置零
		}
		_except(1)
		{
			;
		}
	}
	//退出依附进程
	KeDetachProcess();
}




NTKERNELAPI VOID NTAPI KeAttachProcess(PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeDetachProcess();
void KillProcess(HANDLE pid)
{
	PEPROCESS proc = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PKAPC_STATE pApcState = NULL;


	PsLookupProcessByProcessId((HANDLE)pid, &proc);
	if (proc == 0)
	{

		return;
	}

	//KeAttachProcess(proc);
	//KeDetachProcess()  等都已经过时.所以使用新的
	pApcState = (PKAPC_STATE)ExAllocatePoolWithTag(NonPagedPool, sizeof(PKAPC_STATE), '1111');
	if (NULL == pApcState)
	{
		ObDereferenceObject(proc);
		return;
	}
	__try {
		KeStackAttachProcess(proc, pApcState);
		//KeAttachProcess(proc);
		for (int i = 0x10000; i < 0x20000000; i += PAGE_SIZE)
		{
			__try
			{
				memset((PVOID)i, 0, PAGE_SIZE);
			}
			__except (1)
			{
				;       //内部处理异常
			}
		}
		KeUnstackDetachProcess(pApcState);
		//KeDetachProcess();
		ObDereferenceObject(proc);
		return;
	}
	__except (1)
	{
		DbgPrint("强杀出错\r\n");
		KeUnstackDetachProcess(pApcState);
		ObDereferenceObject(proc);
	}


	return;
}


*/