#pragma once

#include "global.h"
#include "context.h"
#include "utils.h"

#define POC_HEADER_SIZE 4096  // 4KB固定大小标识头

typedef struct _POC_FILE_HEADER {
	UCHAR Signature[8];       // 文件标识签名，如"POC_ENC"
	UCHAR AlgorithmType;      // 加密算法类型
	UCHAR KeyHash[32];        // 密钥哈希值
	LONGLONG OriginalSize;    // 原始文件大小
	UCHAR Checksum[16];       // 校验信息
	UCHAR Reserved[POC_HEADER_SIZE - 8 - 1 - 32 - 8 - 16];  // 预留空间
} POC_FILE_HEADER, * PPOC_FILE_HEADER;

typedef struct _POC_ENCRYPTION_HEADER
{
	CHAR Flag[32];
	WCHAR FileName[POC_MAX_NAME_LENGTH];
	LONGLONG FileSize;
	BOOLEAN IsCipherText;
	CHAR EncryptionAlgorithmType[32];
	CHAR KeyAndCiphertextHash[32];

}POC_ENCRYPTION_HEADER, * PPOC_ENCRYPTION_HEADER;

extern POC_ENCRYPTION_HEADER EncryptionHeader;

extern POC_FILE_HEADER EncryptionHeader;

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

NTSTATUS PocAppendEncHeaderToFile(
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

KSTART_ROUTINE PocAppendEncHeaderThread;

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
