#pragma once

#include <����.h>



NTSTATUS ZwKillProcess(HANDLE pid)//ǿ��ɱ����
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
	//�򿪽��̣���������Ч�����������
	status = ZwOpenProcess(&hProcess, 1, &oa, &ClientId);
	if (NT_SUCCESS(status))
	{
		DbgPrint("[��������]OpenProcess�ɹ�,����ID: %d", hProcess);
		ZwTerminateProcess(hProcess, 0);
		ZwClose(hProcess);
		return status;
	};
	DbgPrint("[��������]OpenProcessʧ��,����ID: %d", hProcess);
	return FALSE;
}

NTSTATUS ZwKillProcessByhProcess(HANDLE hProcess)//ǿ��ɱ����
{

	if (hProcess)
	{
		DbgPrint("[��������]����ɹ�,����ID: %d", hProcess);
		ZwTerminateProcess(hProcess, 0);
		ZwClose(hProcess);
		return STATUS_SUCCESS;
	};
	DbgPrint("[��������]����ʧ��,����ID: %d", hProcess);
	return FALSE;
}

/*
//������0
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

//�ڴ����㷨��������
/*
NTKERNELAPI VOID NTAPI KeAttachProcess(PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeDetachProcess();
//�ڴ����㷨��������
void PVASE()
{
	SIZE_T i = 0;
	//��������
	KeAttachProcess((PEPROCESS)0xFFFFFA8003ABDB30); //�����Ϊָ�����̵� EPROCESS
	for (i = 0x10000; i < 0x20000000; i += PAGE_SIZE)
	{
		__try
		{
			memset((PVOID)i, 0, PAGE_SIZE); //�ѽ����ڴ�ȫ������
		}
		_except(1)
		{
			;
		}
	}
	//�˳���������
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
	//KeDetachProcess()  �ȶ��Ѿ���ʱ.����ʹ���µ�
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
				;       //�ڲ������쳣
			}
		}
		KeUnstackDetachProcess(pApcState);
		//KeDetachProcess();
		ObDereferenceObject(proc);
		return;
	}
	__except (1)
	{
		DbgPrint("ǿɱ����\r\n");
		KeUnstackDetachProcess(pApcState);
		ObDereferenceObject(proc);
	}


	return;
}


*/