#ifndef _FORCE_DELETE_H_
#define _FORCE_DELETE_H_


#include "IrpFile.h"


// ǿ��ɾ���ļ�
NTSTATUS ForceDeleteFile(UNICODE_STRING ustrFileName);

//�����ļ�
PFILE_OBJECT ProtectFile(UNICODE_STRING ustrFileName);

//ȡ���ļ�����
BOOLEAN UnprotectFile(PFILE_OBJECT pFileObject);

#endif