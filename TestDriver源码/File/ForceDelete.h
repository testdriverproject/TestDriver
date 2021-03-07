#ifndef _FORCE_DELETE_H_
#define _FORCE_DELETE_H_


#include "IrpFile.h"


// 强制删除文件
NTSTATUS ForceDeleteFile(UNICODE_STRING ustrFileName);

//保护文件
PFILE_OBJECT ProtectFile(UNICODE_STRING ustrFileName);

//取消文件保护
BOOLEAN UnprotectFile(PFILE_OBJECT pFileObject);

#endif