#pragma once

#include "global.h"
#include "context.h"
#include "utils.h"

#define POC_HEADER_SIZE 4096  // 4KB�̶���С��ʶͷ

// ��������ʶͷ�ṹ�����ʶβԪ����һ�£��洢���ļ�ͷ����
typedef struct _POC_ENCRYPTION_HEADER
{
	CHAR Flag[32];               // ��ʶͷ��������"FOKS-TROT-HEADER"��
	WCHAR FileName[POC_MAX_NAME_LENGTH];  // �ļ���
	LONGLONG FileSize;           // ԭʼ�ļ���С��������ʶͷ��
	LONGLONG HeaderSize;            // ��ʶͷ�����С������ƫ�Ƽ��㣩
	BOOLEAN IsCipherText;        // �Ƿ����
	CHAR EncryptionAlgorithmType[32];  // �����㷨
	CHAR KeyAndCiphertextHash[32];     // ��ϣУ��
	
} POC_ENCRYPTION_HEADER, * PPOC_ENCRYPTION_HEADER;

extern POC_ENCRYPTION_HEADER EncryptionHeader;  // ��������ʶͷȫ��ʵ��

// ��������ȡ��ʶͷ��������
NTSTATUS PocReadEncryptHeader(
	IN PFLT_INSTANCE Instance,
	IN PFLT_VOLUME Volume,
	IN PWCHAR FileName,
	OUT PPOC_ENCRYPTION_HEADER OutHeader);

// �����������ļ�ʱ��ʼ����ʶͷ�����ԭ��ʶβ����������
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

NTSTATUS PocUpdateEncryptionHeader(  // ���ܣ�����ʱ���±�ʶͷ��̬��Ϣ
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

KSTART_ROUTINE PocUpdateHeaderThread;  // ԭ��Ϊ PocAppendEncTailerThread

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
