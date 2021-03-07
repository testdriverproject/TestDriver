#pragma once


NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS proc);  //��ͣ����
NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS proc);   //�ָ�����


void PauseProcess(ULONG pid)//��ͣ���� ,ԭ�� PsSuspendProcess
{
	PEPROCESS pCurrentEprocess = NULL;
	pCurrentEprocess = LookupProcess((HANDLE)pid);
	if (pCurrentEprocess != NULL)
	{
		PsSuspendProcess(pCurrentEprocess);
		DbgPrint("������̳ɹ�\r\n");
		ObDereferenceObject(pCurrentEprocess);
	}

}


void ResumeProcess(ULONG pid)//�ָ����� ,ԭ�� PsResumeProcess
{
	PEPROCESS pCurrentEprocess = NULL;
	pCurrentEprocess = LookupProcess((HANDLE)pid);
	if (pCurrentEprocess != NULL)
	{
		PsResumeProcess(pCurrentEprocess);
		DbgPrint("�ָ����̳ɹ�\r\n");
		ObDereferenceObject(pCurrentEprocess);
	}

}
