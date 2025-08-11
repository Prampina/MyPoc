#pragma once

#include "global.h"
#include "context.h"
#include "utils.h"

#define POC_HEADER_SIZE 4096  // 4KB固定大小标识头

// 新增：标识头结构（与标识尾元数据一致，存储在文件头部）
typedef struct _POC_ENCRYPTION_HEADER
{
	CHAR Flag[32];               // 标识头特征（如"FOKS-TROT-HEADER"）
	WCHAR FileName[POC_MAX_NAME_LENGTH];  // 文件名
	LONGLONG FileSize;           // 原始文件大小（不含标识头）
	LONGLONG HeaderSize;            // 标识头自身大小（用于偏移计算）
	BOOLEAN IsCipherText;        // 是否加密
	CHAR EncryptionAlgorithmType[32];  // 加密算法
	CHAR KeyAndCiphertextHash[32];     // 哈希校验
	
} POC_ENCRYPTION_HEADER, * PPOC_ENCRYPTION_HEADER;

extern POC_ENCRYPTION_HEADER EncryptionHeader;  // 新增：标识头全局实例

// 新增：读取标识头函数声明
NTSTATUS PocReadEncryptHeader(
	IN PFLT_INSTANCE Instance,
	IN PFLT_VOLUME Volume,
	IN PWCHAR FileName,
	OUT PPOC_ENCRYPTION_HEADER OutHeader);

// 新增：创建文件时初始化标识头（替代原标识尾创建函数）
NTSTATUS PocInitEncryptionHeader(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject,
	IN PWCHAR FileName);

NTSTATUS PocReadFileNoCache(
	IN PFLT_INSTANCE Instance,
	IN PFLT_VOLUME Volume,
	IN PWCHAR FileName,
	IN LARGE_INTEGER ByteOffset,
	IN ULONG ReadLength,
	OUT PCHAR* OutReadBuffer,
	IN OUT PULONG BytesRead);

NTSTATUS PocWriteFileIntoCache(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject,
	IN LARGE_INTEGER ByteOffset,
	IN PCHAR WriteBuffer,
	IN ULONG WriteLength);

NTSTATUS PocCreateFileForEncHeader(
	IN PCFLT_RELATED_OBJECTS FltObjects,
	IN PPOC_STREAM_CONTEXT StreamContext,
	IN PWCHAR ProcessName);

NTSTATUS PocUpdateEncryptionHeader(  // 功能：保存时更新标识头动态信息
	IN PFLT_VOLUME Volume,
	IN PFLT_INSTANCE Instance,
	IN PPOC_STREAM_CONTEXT StreamContext);

NTSTATUS PocNtfsFlushAndPurgeCache(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject);

NTSTATUS PocFlushOriginalCache(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName);

NTSTATUS PocReentryToEncrypt(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName);

NTSTATUS PocReentryToDecrypt(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName);

KSTART_ROUTINE PocUpdateHeaderThread;  // 原名为 PocAppendEncTailerThread

NTSTATUS PocReadFileFromCache(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject,
	IN LARGE_INTEGER ByteOffset,
	IN PCHAR ReadBuffer,
	IN ULONG ReadLength);

NTSTATUS PocInitFlushFileObject(
	IN PWCHAR FileName,
	IN OUT PFILE_OBJECT* FileObject);

NTSTATUS PocFindOrCreateStreamContextOutsite(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName,
	IN BOOLEAN CreateIfNotFound);

VOID PocPurgeCache(
	IN PWCHAR FileName,
	IN PFLT_INSTANCE Instance,
	IN PSECTION_OBJECT_POINTERS SectionObjectPointers);
