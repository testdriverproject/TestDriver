#pragma once


NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS proc);  //暂停进程
NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS proc);   //恢复进程


void PauseProcess(ULONG pid)//暂停进程 ,原型 PsSuspendProcess
{
	PEPROCESS pCurrentEprocess = NULL;
	pCurrentEprocess = LookupProcess((HANDLE)pid);
	if (pCurrentEprocess != NULL)
	{
		PsSuspendProcess(pCurrentEprocess);
		DbgPrint("挂起进程成功\r\n");
		ObDereferenceObject(pCurrentEprocess);
	}

}


void ResumeProcess(ULONG pid)//恢复进程 ,原型 PsResumeProcess
{
	PEPROCESS pCurrentEprocess = NULL;
	pCurrentEprocess = LookupProcess((HANDLE)pid);
	if (pCurrentEprocess != NULL)
	{
		PsResumeProcess(pCurrentEprocess);
		DbgPrint("恢复进程成功\r\n");
		ObDereferenceObject(pCurrentEprocess);
	}

}
