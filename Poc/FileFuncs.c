
#include "filefuncs.h"
#include "context.h"
#include "process.h"
#include "global.h"
#include "utils.h"
#include "write.h"
#include "cipher.h"

POC_ENCRYPTION_HEADER EncryptionHeader = { 0 };

NTSTATUS PocReadFileNoCache(
    IN PFLT_INSTANCE Instance,
    IN PFLT_VOLUME Volume,
    IN PWCHAR FileName,
    IN LARGE_INTEGER ByteOffset,
    IN ULONG ReadLength,
    OUT PCHAR* OutReadBuffer, 
    IN OUT PULONG BytesRead)
{
    
    //ReadBuffer��Ҫ��������STATUS_SUCCESS�󣬵������ֶ��ͷ�
    //FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, READ_BUFFER_TAG);

    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FileName is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == BytesRead)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->BytesRead is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    PAGED_CODE();

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_VOLUME_CONTEXT VolumeContext = NULL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    LONGLONG FileSize = 0;
    PCHAR ReadBuffer = NULL;
    LARGE_INTEGER byteOffset = { 0 };
    ULONG readLength = 0;

    const ULONG HEADER_SIZE = sizeof(POC_ENCRYPTION_HEADER);

    byteOffset.QuadPart = ByteOffset.QuadPart + HEADER_SIZE;
    readLength = ReadLength;

    Status = FltGetVolumeContext(gFilterHandle, Volume, &VolumeContext);

    if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize) 
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltGetVolumeContext failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);


    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
        &hFile,
        &FileObject,
        GENERIC_READ,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_NO_INTERMEDIATE_BUFFERING,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltCreateFileEx failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

    FileSize = PocQueryEndOfFileInfo(Instance, FileObject);

    // ҵ���������ɶ�ȡ��Χ���ܴ�С - ͷ����С
    const LONGLONG MaxBusinessSize = FileSize - HEADER_SIZE;

    // У���߼�ƫ���Ƿ񳬳�ҵ�����ݷ�Χ
    if (ByteOffset.QuadPart >= MaxBusinessSize) {  // ע�⣺��ԭʼ�߼�ƫ���ж�
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->End of business data.\n"));
        Status = STATUS_END_OF_FILE;
        goto EXIT;
    }
    // ���ƶ�ȡ���Ȳ�����ҵ������ʣ�෶Χ
    if (ByteOffset.QuadPart + readLength > MaxBusinessSize) {
        readLength = (ULONG)(MaxBusinessSize - ByteOffset.QuadPart);
    }

    readLength = ROUND_TO_SIZE(readLength, VolumeContext->SectorSize);
    byteOffset.QuadPart = ROUND_TO_SIZE(byteOffset.QuadPart, VolumeContext->SectorSize);

    //FLTFL_IO_OPERATION_NON_CACHED
    //The ReadBuffer that the Buffer parameter points to must be aligned 
    //in accordance with the alignment requirement of the underlying storage device. 
    //To allocate such an aligned buffer, call FltAllocatePoolAlignedWithTag.
    ReadBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, readLength, READ_BUFFER_TAG);

    if (NULL == ReadBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltAllocatePoolAlignedWithTag ReadBuffer failed.\n"));
        Status = STATUS_UNSUCCESSFUL;
        goto EXIT;
    }

    RtlZeroMemory(ReadBuffer, readLength);

    Status = FltReadFileEx(
        Instance, 
        FileObject, 
        &byteOffset, 
        readLength, 
        ReadBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | 
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, 
        BytesRead, 
        NULL, 
        NULL, 
        NULL, 
        NULL);

    if (!NT_SUCCESS(Status))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltReadFileEx failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

    *OutReadBuffer = ReadBuffer;

EXIT:

    if (NULL != VolumeContext)
    {
        FltReleaseContext(VolumeContext);
        VolumeContext = NULL;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (!NT_SUCCESS(Status) && NULL != ReadBuffer)
    {
        FltFreePoolAlignedWithTag(Instance, ReadBuffer, READ_BUFFER_TAG);
        ReadBuffer = NULL;
        *OutReadBuffer = NULL;
    }

	return Status;
}

// ��ʶͷ��ȡ����
NTSTATUS PocReadEncryptHeader(
    IN PFLT_INSTANCE Instance,
    IN PFLT_VOLUME Volume,
    IN PWCHAR FileName,
    OUT PPOC_ENCRYPTION_HEADER OutHeader)
{
    if (NULL == FileName || NULL == OutHeader)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadEncryptHeader->Invalid parameters\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status;
    PCHAR ReadBuffer = NULL;
    ULONG BytesRead = 0;
    LARGE_INTEGER ByteOffset = { 0 };  // ���ļ�ͷ����0ƫ�ƣ���ȡ

    // ��ȡ��ʶͷ��С�����ݣ��̶�Ϊ�ṹ���С��
    Status = PocReadFileNoCache(
        Instance,
        Volume,
        FileName,
        ByteOffset,
        sizeof(POC_ENCRYPTION_HEADER),
        &ReadBuffer,
        &BytesRead);

    if (!NT_SUCCESS(Status) || BytesRead != sizeof(POC_ENCRYPTION_HEADER))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadEncryptHeader->Read failed. Status=0x%x\n", Status));
        goto EXIT;
    }

    // ������У���ʶͷ
    RtlCopyMemory(OutHeader, ReadBuffer, sizeof(POC_ENCRYPTION_HEADER));
    if (strncmp(OutHeader->Flag, EncryptionHeader.Flag, strlen(EncryptionHeader.Flag)) != 0)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadEncryptHeader->Invalid header flag\n"));
        Status = STATUS_FILE_CORRUPT;
        goto EXIT;
    }

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadEncryptHeader->Read header for %ws success\n", FileName));

EXIT:
    if (ReadBuffer != NULL)
    {
        FltFreePoolAlignedWithTag(Instance, ReadBuffer, READ_BUFFER_TAG);
    }
    return Status;
}


NTSTATUS PocReadFileFromCache(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    IN LARGE_INTEGER ByteOffset,
    IN PCHAR ReadBuffer,
    IN ULONG ReadLength)
{
    if (NULL == ReadBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileFromCache->ReadBuffer is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    Status = FltReadFileEx(Instance, FileObject, &ByteOffset, ReadLength, ReadBuffer, 0, NULL, NULL, NULL, NULL, NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileFromCache->FltReadFileEx failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

EXIT:

    return Status;
}


NTSTATUS PocWriteFileIntoCache(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    IN LARGE_INTEGER ByteOffset,
    IN PCHAR WriteBuffer,
    IN ULONG WriteLength)
{

    if (NULL == WriteBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocWriteFileIntoCache->WriteBuffer is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    ULONG BytesWritten = 0;

    // ͷ����С
    const ULONG HEADER_SIZE = sizeof(POC_ENCRYPTION_HEADER);
    // ����д��ƫ�ƣ�ҵ�����ݴ�HEADER_SIZE��ʼ
    LARGE_INTEGER actualOffset = ByteOffset;
    actualOffset.QuadPart += HEADER_SIZE;  // �����޸ģ�����ͷ��ƫ��

    Status = FltWriteFileEx(Instance, FileObject, &actualOffset, WriteLength, WriteBuffer, 0, &BytesWritten, NULL, NULL, NULL, NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocWriteFileIntoCache->FltWriteFileEx failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

EXIT:

    return Status;
}


NTSTATUS PocCreateFileForEncHeader(
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PPOC_STREAM_CONTEXT StreamContext,
    IN PWCHAR ProcessName)
{

    if (NULL == StreamContext)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncHeader->StreamContext is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == StreamContext->FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncHeader->StreamContext->FileName is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    LONGLONG FileSize = 0;
    LARGE_INTEGER ByteOffset = { 0 };
    PCHAR OutReadBuffer = NULL;
    ULONG BytesRead = 0;
    // ͷ����С
    const ULONG HEADER_SIZE = sizeof(POC_ENCRYPTION_HEADER);

    FileSize = PocQueryEndOfFileInfo(FltObjects->Instance, FltObjects->FileObject);

    // ���ļ���СС��ͷ����С����Ϊδ��ʼ��
    if (FileSize < HEADER_SIZE) {
        Status = STATUS_END_OF_FILE;
        goto EXIT;
    }

    // ��ȡͷ����ƫ��0������Ϊͷ����С��
    ByteOffset.QuadPart = 0;  // �����޸ģ����ļ���ʼλ�ö�ȡͷ��

    Status = PocReadFileNoCache(
        FltObjects->Instance,
        FltObjects->Volume,
        StreamContext->FileName,
        ByteOffset,
        sizeof(POC_ENCRYPTION_HEADER),  // ֻ��ȡ����ͷ��С
        &OutReadBuffer,
        &BytesRead);

    if (!NT_SUCCESS(Status) || NULL == OutReadBuffer || BytesRead != sizeof(POC_ENCRYPTION_HEADER))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReadFileNoCache failed. ProcessName = %ws Status = 0x%x\n", __FUNCTION__, ProcessName, Status));
        goto EXIT;
    }
    // У��ͷ����ʶ
    PPOC_ENCRYPTION_HEADER header = (PPOC_ENCRYPTION_HEADER)OutReadBuffer;
    // У�����ͷ��ʶ���ļ���
    if (strncmp(((PPOC_ENCRYPTION_HEADER)OutReadBuffer)->Flag, EncryptionHeader.Flag,
        strlen(EncryptionHeader.Flag)) == 0 &&
        wcsncmp(((PPOC_ENCRYPTION_HEADER)OutReadBuffer)->FileName, StreamContext->FileName,
            POC_MAX_NAME_LENGTH) == 0)  // �ù̶����ȱ���wcslen����
    {

        /*
        * �������غ��ļ�����л�����߱��ڴ�ӳ���д������һ�»��壬��ֹ��������
        * ֻҪ��������֮ǰ�л��壬��Ҫ�����
        */
        if (0 == StreamContext->IsCipherText)
        {
            if (FltObjects->FileObject->SectionObjectPointer->DataSectionObject != NULL)
            {
                Status = PocNtfsFlushAndPurgeCache(FltObjects->Instance, FltObjects->FileObject);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncHeader->PocNtfsFlushAndPurgeCache failed. Status = 0x%x.\n", Status));
                }
                else
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncHeader->File has been opened. Flush and purge cache.\n"));
                }
            }
        }

        // �����������ģ�ҵ�����ݴ�С = �ܴ�С - ͷ����С��
        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
        if (0 == StreamContext->FileSize) {
            StreamContext->FileSize = header->FileSize;  // �� FileSize - HEADER_SIZE
        }
        if (0 == StreamContext->IsCipherText) {
            StreamContext->IsCipherText = header->IsCipherText;
        }
        
        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

        Status = POC_FILE_HAS_ENCRYPTION_HEADER;

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n%s->File %ws has encryption header FileSize = %I64d ProcessName = %ws.\n",
            __FUNCTION__,
            StreamContext->FileName,
            StreamContext->FileSize,
            ProcessName));
    }
    else if(strncmp(((PPOC_ENCRYPTION_HEADER)OutReadBuffer)->Flag, EncryptionHeader.Flag,
        strlen(EncryptionHeader.Flag)) == 0)
    {
        if (0 == StreamContext->IsCipherText)
        {
            if (FltObjects->FileObject->SectionObjectPointer->DataSectionObject != NULL)
            {
                Status = PocNtfsFlushAndPurgeCache(FltObjects->Instance, FltObjects->FileObject);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncHeader->PocNtfsFlushAndPurgeCache failed. Status = 0x%x.\n", Status));
                }
                else
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncHeader->File has been opened. Flush and purge cache.\n"));
                }
            }
        }

        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

        if (0 == StreamContext->FileSize)
        {
            StreamContext->FileSize = ((PPOC_ENCRYPTION_HEADER)OutReadBuffer)->FileSize;
        }
        if (0 == StreamContext->IsCipherText)
        {
            StreamContext->IsCipherText = ((PPOC_ENCRYPTION_HEADER)OutReadBuffer)->IsCipherText;
        }

        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

        Status = POC_HEADER_WRONG_FILE_NAME;

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Ciphetext->other extension->target extension. FileSize = %I64d ProcessName = %ws\n",
            __FUNCTION__,
            StreamContext->FileSize,
            ProcessName));
    }


EXIT:
    if (NULL != OutReadBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, OutReadBuffer, READ_BUFFER_TAG);
        OutReadBuffer = NULL;
    }

    return Status;
}


NTSTATUS PocUpdateEncryptionHeader(
    IN PFLT_VOLUME Volume,
    IN PFLT_INSTANCE Instance,
    IN PPOC_STREAM_CONTEXT StreamContext)
{
    /**
     * @brief �����ļ��ļ���ͷ����Ϣ�������ļ���С������״̬���ļ����ȣ�
     * @param Volume ��������ڻ�ȡ�������ģ�
     * @param Instance ΢ɸѡʵ��
     * @param StreamContext �ļ��������ģ������FileName��HeaderSize�ȹؼ���Ϣ��
     * @return STATUS_SUCCESS �ɹ�������״̬�� ʧ�ܣ�������Ч���ļ�����ʧ�ܵȣ�
     */
    if (NULL == StreamContext || StreamContext->HeaderSize == 0 || NULL == StreamContext->FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->������Ч��StreamContext��HeaderSize��FileNameΪ��\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PPOC_VOLUME_CONTEXT VolumeContext = NULL;
    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    const ULONG HEADER_SIZE = sizeof(POC_ENCRYPTION_HEADER);  // ����ͷ�̶���С
    PCHAR WriteBuffer = NULL;
    ULONG BytesWritten = 0;

    // ��ȡ�������ģ�У��������С��
    Status = FltGetVolumeContext(gFilterHandle, Volume, &VolumeContext);
    if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->��ȡ��������ʧ�ܣ�Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    // ��ʼ���ļ����Ͷ�������
    RtlInitUnicodeString(&uFileName, StreamContext->FileName);
    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // ���ļ���������д�����ͷ��
    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
        &hFile,
        &FileObject,
        GENERIC_WRITE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        0);
    if (STATUS_SUCCESS != Status)
    {
        if (STATUS_OBJECT_NAME_NOT_FOUND == Status || STATUS_OBJECT_PATH_SYNTAX_BAD == Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->�ļ���ɾ����Status = 0x%x\n", __FUNCTION__, Status));
        }
        else
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->���ļ�ʧ�ܣ�Status = 0x%x\n", __FUNCTION__, Status));
        }
        goto EXIT;
    }

    // �������ͷ�����������������룩
    WriteBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, HEADER_SIZE, WRITE_BUFFER_TAG);
    if (NULL == WriteBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->���仺����ʧ��\n", __FUNCTION__));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }
    RtlZeroMemory(WriteBuffer, HEADER_SIZE);

    // ������ͷ���ݣ���ǿ�߽��飩
    RtlMoveMemory(WriteBuffer, &EncryptionHeader, HEADER_SIZE);
    ((PPOC_ENCRYPTION_HEADER)WriteBuffer)->FileSize = StreamContext->FileSize;
    ((PPOC_ENCRYPTION_HEADER)WriteBuffer)->IsCipherText = StreamContext->IsCipherText;

    // �����ļ������Ƴ��ȣ�����Խ�磨����POC_MAX_NAME_LENGTH >= ʵ���ļ������ȣ�
    ULONG copyNameLen = min(POC_MAX_NAME_LENGTH * sizeof(WCHAR), wcslen(StreamContext->FileName) * sizeof(WCHAR) + sizeof(WCHAR));
    RtlMoveMemory(((PPOC_ENCRYPTION_HEADER)WriteBuffer)->FileName, StreamContext->FileName, copyNameLen);

    // д�����ͷ���ļ���ʼλ�ã�У��д�������ԣ�
    LARGE_INTEGER writeOffset = { 0 };  // ���ļ���ͷд��
    Status = FltWriteFileEx(
        Instance,
        FileObject,
        &writeOffset,
        HEADER_SIZE,
        WriteBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        &BytesWritten,
        NULL,
        NULL,
        NULL,
        NULL);
    if (!NT_SUCCESS(Status) || BytesWritten != HEADER_SIZE)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->д�����ͷʧ�ܣ�Status = 0x%x��ʵ��д�� %d �ֽ�\n", __FUNCTION__, Status, BytesWritten));
        goto EXIT;
    }

    // ��ǰ�ر��ļ��������������������ţ�
    FltClose(hFile);
    hFile = NULL;
    ObDereferenceObject(FileObject);
    FileObject = NULL;

    // ����Ӱ�ӽڶ���ָ�루����ͬ����
    if (NULL != StreamContext->ShadowSectionObjectPointers->DataSectionObject)
    {
        // ���´��ļ����ڻ������
        Status = FltCreateFileEx(
            gFilterHandle,
            Instance,
            &hFile,
            &FileObject,
            0,
            &ObjectAttributes,
            &IoStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            0,
            IO_IGNORE_SHARE_ACCESS_CHECK);
        if (STATUS_SUCCESS != Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->���´��ļ�ʧ�ܣ�Status = 0x%x\n", __FUNCTION__, Status));
            goto EXIT;
        }

        // ����Ӱ�ӽڶ���
        FileObject->SectionObjectPointer = StreamContext->ShadowSectionObjectPointers;

        // ��ʼ�����棨�����Ҫ��
        if (NULL == StreamContext->ShadowSectionObjectPointers->SharedCacheMap)
        {
            CHAR dummyBuffer = { 0 };
            LARGE_INTEGER readOffset = { 0 };
            Status = FltReadFileEx(
                Instance,
                FileObject,
                &readOffset,
                sizeof(dummyBuffer),
                &dummyBuffer,
                0,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);
            if (!NT_SUCCESS(Status) && STATUS_END_OF_FILE != Status)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->��ʼ������ʧ�ܣ�Status = 0x%x\n", __FUNCTION__, Status));
                goto EXIT;
            }
        }

        // ͬ�������С
        if (CcIsFileCached(FileObject))
        {
            PFSRTL_ADVANCED_FCB_HEADER fcbHeader = (PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext;
            ExAcquireResourceExclusiveLite(fcbHeader->Resource, TRUE);

            // ���»����С
            CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&fcbHeader->AllocationSize);
            CcPurgeCacheSection(StreamContext->ShadowSectionObjectPointers, NULL, 0, FALSE);

            ExReleaseResourceLite(fcbHeader->Resource);

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                ("%s->ͬ�������С��ɣ��ļ�=%ws�������С=%I64d����Ч���ݳ���=%I64d\n",
                    __FUNCTION__,
                    StreamContext->FileName,
                    fcbHeader->AllocationSize.QuadPart,
                    fcbHeader->ValidDataLength.QuadPart));
        }
    }

    // ����������״̬������������
    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
    StreamContext->IsDirty = FALSE;
    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

    Status = STATUS_SUCCESS;

EXIT:
    // ��Դ����ȷ��������Դ�����ͷţ�
    if (NULL != VolumeContext)
    {
        FltReleaseContext(VolumeContext);
    }
    if (NULL != hFile)
    {
        FltClose(hFile);
    }
    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
    }
    if (NULL != WriteBuffer)
    {
        FltFreePoolAlignedWithTag(Instance, WriteBuffer, WRITE_BUFFER_TAG);
    }

    return Status;
}


NTSTATUS PocNtfsFlushAndPurgeCache(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject)
{
    if (NULL == Instance)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Instance is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == FileObject)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileObject is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PFLT_CALLBACK_DATA Data = NULL;

    Status = FltAllocateCallbackData(Instance, FileObject, &Data);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocNtfsFlushAndPurgeCache->FltAllocateCallbackData failed. Status = 0x%x\n", Status));
        return Status;
    }

    Data->Iopb->MajorFunction = IRP_MJ_FLUSH_BUFFERS;
    Data->Iopb->MinorFunction = IRP_MN_FLUSH_AND_PURGE;
    Data->Iopb->IrpFlags = IRP_SYNCHRONOUS_API;
    FltPerformSynchronousIo(Data);
    
    FltFreeCallbackData(Data);

    return Data->IoStatus.Status;
}


NTSTATUS PocFlushOriginalCache(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName)
{
    if (NULL == Instance)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Instance is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
        &hFile,
        &FileObject,
        0,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    if (CcIsFileCached(FileObject))
    {
        Status = FltFlushBuffers(Instance, FileObject);

        if (STATUS_SUCCESS != Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocFlushOriginalCache->FltFlushBuffers failed. Status = 0x%x\n", Status));
            goto EXIT;
        }
    }


EXIT:

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    return Status;
}


NTSTATUS PocReentryToGetStreamContext(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName,
    OUT PPOC_STREAM_CONTEXT* StreamContext)
{
    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReentryToGetStreamContext->FileName is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    BOOLEAN ContextCreated = FALSE;


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(
        &ObjectAttributes,
        &uFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    Status = ZwCreateFile(
        &hFile,
        0,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReentryToGetStreamContext->ZwCreateFile failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(hFile, STANDARD_RIGHTS_ALL, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReentryToGetStreamContext->ObReferenceObjectByHandle failed ststus = 0x%x.\n", Status));
        goto EXIT;
    }

    Status = PocFindOrCreateStreamContext(
        Instance,
        FileObject,
        FALSE,
        StreamContext,
        &ContextCreated);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReentryToGetStreamContext->PocFindOrCreateStreamContext failed. Status = 0x%x\n", Status));
        goto EXIT;
    }


EXIT:

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (NULL != hFile)
    {
        ZwClose(hFile);
        hFile = NULL;
    }
    
    return Status;
}


NTSTATUS PocReentryToEncrypt(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName)
{
    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_STREAM_CONTEXT StreamContext = NULL;

    LONGLONG FileSize = 0;
    LARGE_INTEGER ByteOffset = { 0 };
    PCHAR ReadBuffer = NULL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };


    Status = PocReentryToGetStreamContext(
        Instance,
        FileName,
        &StreamContext);

    if (STATUS_SUCCESS != Status)
    {
        if (STATUS_NOT_FOUND == Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToGetStreamContext failed. Irrelevent file extension\n", __FUNCTION__));
            Status = POC_IRRELEVENT_FILE_EXTENSION;
        }
        else
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToGetStreamContext failed. Status = 0x%x FileName = %ws\n", 
                __FUNCTION__, Status, FileName));
        }
        goto EXIT;
    }

    if (TRUE == StreamContext->IsCipherText)
    {
        Status = POC_FILE_IS_CIPHERTEXT;

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
            ("%s->%ws is ciphertext. Encrypt failed. FileSize = %I64d.\n",
            __FUNCTION__, FileName, StreamContext->FileSize));

        goto EXIT;
    }

    if(POC_RENAME_TO_ENCRYPT == StreamContext->Flag)
    {
        Status = STATUS_SUCCESS;
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
            ("%s->%ws being rename to encrypt. Encrypt success.\n", __FUNCTION__, FileName));
        goto EXIT;
    }


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(
        &ObjectAttributes, 
        &uFileName, 
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
        NULL, 
        NULL);

    /*
    * ���ﲻ����FltCreateFile����Ϊ������FileObject�Ƿ�����ģ������FileObject�Ͻ����Ļ���Ҳ�Ƿ�����ģ�
    * ���ǵ�PreWrite�޷����ܺ���PocWriteFileIntoCacheд������ݡ�
    * ���һ�����ļ�������Ȩ����֮ǰ��û�н������壬��ô����ͻ���������������Ȩ����ʵ������ʧ�ܵġ�
    */

    Status = ZwCreateFile(
        &hFile,
        GENERIC_READ,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwCreateFile failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(
        hFile,
        STANDARD_RIGHTS_ALL,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&FileObject,
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObReferenceObjectByHandle failed. Status = 0x%x.\n", __FUNCTION__, Status));
        goto EXIT;
    }

    /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n %s->Process = %p Thread = %p Fcb = %p Ccb = %p Resource = %p PagingIoResource = %p.\n\n",
        __FUNCTION__,
        PsGetCurrentProcess(),
        PsGetCurrentThread(),
        (PCHAR)FileObject->FsContext,
        FileObject->FsContext2,
        ((PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext)->Resource,
        ((PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext)->PagingIoResource));*/

    FileSize = PocQueryEndOfFileInfo(Instance, FileObject);

    if(0 == FileSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileSize is zero.\n", __FUNCTION__));
        Status = STATUS_SUCCESS;
        goto EXIT;
    }

    ReadBuffer = ExAllocatePoolWithTag(PagedPool, FileSize, READ_BUFFER_TAG);

    if (NULL == ReadBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag ReadBuffer failed.\n", __FUNCTION__));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }

    RtlZeroMemory(ReadBuffer, FileSize);

    ByteOffset.QuadPart = 0;

    Status = PocReadFileFromCache(
        Instance,
        FileObject,
        ByteOffset,
        ReadBuffer,
        (ULONG)FileSize);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReadFileFromCache failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }


    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }


    RtlZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    InitializeObjectAttributes(
        &ObjectAttributes,
        &uFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);


    Status = ZwCreateFile(
        &hFile,
        GENERIC_WRITE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_WRITE_THROUGH,
        NULL,
        0);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwCreateFile failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    PocUpdateFlagInStreamContext(StreamContext, 0);

    Status = ObReferenceObjectByHandle(
        hFile, 
        STANDARD_RIGHTS_ALL, 
        *IoFileObjectType, 
        KernelMode, 
        (PVOID*)&FileObject, 
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObReferenceObjectByHandle failed. Status = 0x%x.\n", __FUNCTION__, Status));
        goto EXIT;
    }


    ByteOffset.QuadPart = 0;

    /*
    * ���ﲻ����FltWriteFileEx����Ϊ���Ļ���д�Ƿ�����ģ�16���ֽ����ڵ��ļ�
    * ������Ҫ����д�������뵽minifilter��ȥ��չ�ļ���С��
    */
    ZwWriteFile(
        hFile, 
        NULL, 
        NULL, 
        NULL, 
        &IoStatusBlock, 
        ReadBuffer, 
        (ULONG)FileSize, 
        &ByteOffset, 
        NULL);


    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwWriteFile failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n%s->success. FileName = %ws FileSize = %I64d.\n",
        __FUNCTION__,
        FileName,
        ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->FileSize.QuadPart));

EXIT:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (NULL != ReadBuffer)
    {
        ExFreePoolWithTag(ReadBuffer, READ_BUFFER_TAG);
        ReadBuffer = NULL;
    }

    if (NULL != hFile)
    {
        ZwClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    return Status;
}


NTSTATUS PocReentryToDecrypt(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName)
{
    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_STREAM_CONTEXT StreamContext = NULL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    LONGLONG FileSize = 0;
    LARGE_INTEGER ByteOffset = { 0 };
    
    PCHAR ReadBuffer = NULL;
    PCHAR WriteBuffer = NULL;

    ULONG WriteLength = 0, BytesWritten = 0;

    Status = PocReentryToGetStreamContext(
        Instance, 
        FileName, 
        &StreamContext);

    if (STATUS_SUCCESS != Status)
    {
        if (STATUS_NOT_FOUND == Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToGetStreamContext failed. Irrelevent file extension\n", __FUNCTION__));
            Status = POC_IRRELEVENT_FILE_EXTENSION;
        }
        else
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToGetStreamContext failed. Status = 0x%x\n", __FUNCTION__, Status));
        }
        goto EXIT;
    }

    if (FALSE == StreamContext->IsCipherText)
    {
        Status = POC_FILE_IS_PLAINTEXT;
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->%ws is plaintext. Decrypt failed.\n", __FUNCTION__, FileName));
        goto EXIT;
    }

    PocUpdateFlagInStreamContext(StreamContext, 0);

    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(
        &ObjectAttributes,
        &uFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    Status = ZwCreateFile(
        &hFile,
        GENERIC_READ,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwCreateFile failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(
        hFile, 
        STANDARD_RIGHTS_ALL, 
        *IoFileObjectType, 
        KernelMode, 
        (PVOID*)&FileObject, 
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObReferenceObjectByHandle failed. Status = 0x%x.\n", __FUNCTION__, Status));
        goto EXIT;
    }

    if (FileObject->SectionObjectPointer == StreamContext->ShadowSectionObjectPointers)
    {
        if (TRUE == StreamContext->IsReEncrypted)
        {
            /*
            * PrivateCacheMapҪ��0�������ļ�ϵͳ�������������壬�������ﲻ������ˣ�
            * ��Ϊ��PostCreate�����״̬���ļ���������ʲô���̣���ָ�����Ļ��塣
            */
            FileObject->SectionObjectPointer = StreamContext->OriginSectionObjectPointers;
            FileObject->PrivateCacheMap = NULL;
        }
        else
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Unauthorized process can't decrypt file.\n", __FUNCTION__));
            Status = POC_IS_UNAUTHORIZED_PROCESS;
            goto EXIT;
        }
    }

    FileSize = StreamContext->FileSize;

    ReadBuffer = ExAllocatePoolWithTag(PagedPool, FileSize, READ_BUFFER_TAG);

    if (NULL == ReadBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag ReadBuffer failed.\n", __FUNCTION__));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }
    
    RtlZeroMemory(ReadBuffer, FileSize);

    ByteOffset.QuadPart = 0;

    Status = PocReadFileFromCache(
        Instance, 
        FileObject,
        ByteOffset,
        ReadBuffer,
        (ULONG)FileSize);


    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReadFileFromCache failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }


    Status = PocSetEndOfFileInfo(
        Instance,
        FileObject,
        FileSize);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocSetEndOfFileInfo failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    if (NULL != hFile)
    {
        ZwClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }




    RtlZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    InitializeObjectAttributes(
        &ObjectAttributes,
        &uFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
        &hFile,
        &FileObject,
        GENERIC_WRITE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_NO_INTERMEDIATE_BUFFERING,
        NULL,
        0,
        0);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }


    WriteLength = ROUND_TO_PAGES(FileSize);

    WriteBuffer= FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, WriteLength, WRITE_BUFFER_TAG);

    if (NULL == WriteBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltAllocatePoolAlignedWithTag WriteBuffer failed.\n", __FUNCTION__));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }

    RtlZeroMemory(WriteBuffer, WriteLength);

    RtlMoveMemory(WriteBuffer, ReadBuffer, FileSize);

    ByteOffset.QuadPart = 0;

    Status = FltWriteFileEx(
        Instance,
        FileObject,
        &ByteOffset,
        WriteLength,
        WriteBuffer,
        FLTFL_IO_OPERATION_NON_CACHED |
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET |
        FLTFL_IO_OPERATION_PAGING |
        FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING,
        &BytesWritten,
        NULL,
        NULL,
        NULL,
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltWriteFileEx failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->success. FileName = %ws FileSize = %I64d.\n\n",
        __FUNCTION__,
        FileName,
        ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->FileSize.QuadPart));

    PocUpdateFlagInStreamContext(StreamContext, 0);

    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

    StreamContext->IsCipherText = FALSE;
    StreamContext->FileSize = 0;
    RtlZeroMemory(StreamContext->FileName, POC_MAX_NAME_LENGTH * sizeof(WCHAR));

    StreamContext->IsReEncrypted = FALSE;

    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
    

EXIT:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (NULL != ReadBuffer)
    {
        ExFreePoolWithTag(ReadBuffer, READ_BUFFER_TAG);
        ReadBuffer = NULL;
    }

    if (NULL != WriteBuffer)
    {
        FltFreePoolAlignedWithTag(Instance, WriteBuffer, WRITE_BUFFER_TAG);
        WriteBuffer = NULL;
    }

    return Status;
}


VOID PocUpdateHeaderThread(IN PVOID StartContext)  // ����������ԭ��Ϊ PocAppendEncTailerThread
{
    PPOC_STREAM_CONTEXT StreamContext = (PPOC_STREAM_CONTEXT)StartContext;
    if (NULL == StreamContext)
        return;

    // ȷ���ڲ���ǰ��ȡ��Դ������ֹ��������
    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

    // ע�ͣ���ԭ��д��β��ʶ�ĵ��ø�Ϊ����ͷ��ʶ
    NTSTATUS status = PocUpdateEncryptionHeader(
        StreamContext->Volume,
        StreamContext->Instance,
        StreamContext
    );

    if (NT_SUCCESS(status))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->��ʶͷ���³ɹ�. File = %ws\n",
            __FUNCTION__, StreamContext->FileName));
    }
    else
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->��ʶͷ����ʧ��. File = %ws, Status = 0x%x\n",
            __FUNCTION__, StreamContext->FileName, status));
    }

    // �ͷ���Դ��
    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

    FltReleaseContext(StreamContext);
}



NTSTATUS PocInitFlushFileObject(
    IN PWCHAR FileName,
    IN OUT PFILE_OBJECT* FileObject)
{

    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateFile(
        &hFile,
        0,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwCreateFile failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(
        hFile,
        STANDARD_RIGHTS_ALL,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)FileObject,
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObReferenceObjectByHandle failed. Status = 0x%x.\n", __FUNCTION__, Status));
        goto EXIT;
    }


EXIT:

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    return Status;
}


NTSTATUS PocFindOrCreateStreamContextOutsite(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName,
    IN BOOLEAN CreateIfNotFound)
{
    if (NULL == Instance)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Instance is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
        &hFile,
        &FileObject,
        0,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (STATUS_SUCCESS != Status)
    {
        //PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx failed. Status = 0x%x. FileName = %ws.\n", __FUNCTION__, Status, FileName));
        goto EXIT;
    }

    Status = PocFindOrCreateStreamContext(
        Instance,
        FileObject,
        CreateIfNotFound,
        &StreamContext,
        &ContextCreated);

    if (STATUS_SUCCESS != Status)
    {
        if (CreateIfNotFound)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocFindOrCreateStreamContext failed. Status = 0x%x.\n",
                __FUNCTION__, Status));
        }
        goto EXIT;
    }

    Status = STATUS_SUCCESS;

EXIT:

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (NULL != hFile)
    {
        ZwClose(hFile);
        hFile = NULL;
    }

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return Status;
}


VOID PocPurgeCache(
    IN PWCHAR FileName,
    IN PFLT_INSTANCE Instance,
    IN PSECTION_OBJECT_POINTERS SectionObjectPointers)
{
    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);


    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
        &hFile,
        &FileObject,
        0,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltCreateFileEx failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->Resource);

    CcPurgeCacheSection(SectionObjectPointers, NULL, 0, FALSE);

    ExReleaseResourceAndLeaveCriticalRegion(((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->Resource);

EXIT:

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

}

// ��������ʼ����ʶͷ���ļ�����ʱд�룩
NTSTATUS PocInitEncryptionHeader(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    IN PWCHAR FileName)
{
    if (NULL == Instance || NULL == FileObject || NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitEncryptionHeader->Invalid parameters\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PPOC_VOLUME_CONTEXT VolumeContext = NULL;
    PCHAR HeaderBuffer = NULL;
    LARGE_INTEGER ByteOffset = { 0 }; // д���ļ�ͷ����0ƫ�ƣ�
    ULONG BytesWritten = 0;
    ULONG HeaderSize = sizeof(POC_ENCRYPTION_HEADER);

    // ��ȡ����Ϣ�����ڶ��룩
    PFLT_VOLUME Volume = NULL;

    // ��ͨ��ʵ����ȡ��ֱ���ڵ��ô����������
    Status = FltGetVolumeFromInstance(Instance, &Volume);
    if (!NT_SUCCESS(Status)) {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitEncryptionHeader->FltGetVolumeFromInstance failed: 0x%x\n", Status));
        goto EXIT;
    }

    // �ٻ�ȡ��������
    Status = FltGetVolumeContext(gFilterHandle, Volume, &VolumeContext);
    if (!NT_SUCCESS(Status) || VolumeContext->SectorSize == 0) {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitEncryptionHeader->Get volume context failed: 0x%x\n", Status));
        goto EXIT;
    }

    // �������Ļ�����
    HeaderBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, HeaderSize, WRITE_BUFFER_TAG);
    if (NULL == HeaderBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitEncryptionHeader->Allocate buffer failed\n"));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }
    RtlZeroMemory(HeaderBuffer, HeaderSize);

    // ����ʶͷ�̶���Ϣ
    strncpy_s(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->Flag, sizeof(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->Flag),
        "FOKS-TROT-HEADER", _TRUNCATE); // �̶���ʶ
    wcsncpy_s(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->FileName, POC_MAX_NAME_LENGTH,
        FileName, _TRUNCATE); // �ļ���
    ((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->HeaderSize = HeaderSize; // ��ʶͷ�����С
    ((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->IsCipherText = FALSE; // ��ʼΪδ����
    strncpy_s(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->EncryptionAlgorithmType,
        sizeof(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->EncryptionAlgorithmType),
        "AES-256", _TRUNCATE); // Ĭ���㷨

    // д���ʶͷ���ļ�
    Status = FltWriteFileEx(
        Instance,
        FileObject,
        &ByteOffset,
        HeaderSize,
        HeaderBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        &BytesWritten,
        NULL,
        NULL,
        NULL,
        NULL);

    if (!NT_SUCCESS(Status) || BytesWritten != HeaderSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitEncryptionHeader->Write header failed: 0x%x, written: %d\n",
            Status, BytesWritten));
        goto EXIT;
    }

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitEncryptionHeader->Init header for %ws success\n", FileName));
    Status = STATUS_SUCCESS;

EXIT:
    if (VolumeContext != NULL)
    {
        FltReleaseContext(VolumeContext);
    }
    if (HeaderBuffer != NULL)
    {
        FltFreePoolAlignedWithTag(Instance, HeaderBuffer, WRITE_BUFFER_TAG);
    }
    return Status;
}

// ���������ļ���ӱ�ʶͷ���߳��е��ã�
NTSTATUS PocAppendEncHeaderToFile(
    IN PFLT_VOLUME Volume,
    IN PFLT_INSTANCE Instance,
    IN PPOC_STREAM_CONTEXT StreamContext)
{
    if (NULL == Volume || NULL == Instance || NULL == StreamContext || NULL == StreamContext->FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAppendEncHeaderToFile->Invalid parameters\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status;
    const ULONG HEADER_SIZE = sizeof(POC_ENCRYPTION_HEADER);
    PFILE_OBJECT FileObject = NULL;
    LONGLONG FileSize = 0;

    // ���ļ���ȡ��ǰ��С
    Status = PocInitFlushFileObject(StreamContext->FileName, &FileObject);
    if (!NT_SUCCESS(Status) || NULL == FileObject)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Open file failed: 0x%x\n", __FUNCTION__, Status));
        return Status;
    }

    // ��ȡ����ͷ���������ڣ�
    POC_ENCRYPTION_HEADER header = { 0 };
    LARGE_INTEGER offset = { 0 };
    PCHAR buffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, HEADER_SIZE, READ_BUFFER_TAG);
    if (NULL == buffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }

    // ��ȡ��ǰͷ��
    Status = FltReadFileEx(Instance, FileObject, &offset, HEADER_SIZE, buffer, 0, NULL, NULL, NULL, NULL, NULL);
    if (NT_SUCCESS(Status))
    {
        RtlCopyMemory(&header, buffer, HEADER_SIZE);
    }
    else if (STATUS_END_OF_FILE == Status)
    {
        // �ļ�δ��ʼ��ͷ����ʹ��Ĭ��ֵ
        RtlZeroMemory(&header, HEADER_SIZE);
        strncpy_s(header.Flag, sizeof(header.Flag), "FOKS-TROT-HEADER", _TRUNCATE);
        wcsncpy_s(header.FileName, POC_MAX_NAME_LENGTH, StreamContext->FileName, _TRUNCATE);
        header.HeaderSize = HEADER_SIZE;
    }
    else
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Read header failed: 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    // ����ͷ����Ϣ
    header.FileSize = StreamContext->FileSize;
    header.IsCipherText = StreamContext->IsCipherText;

    // д��ͷ��
    offset.QuadPart = 0;
    RtlCopyMemory(buffer, &header, HEADER_SIZE);
    Status = FltWriteFileEx(Instance, FileObject, &offset, HEADER_SIZE, buffer, 0, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(Status))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Write header failed: 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    Status = STATUS_SUCCESS;

EXIT:
    if (buffer != NULL)
        FltFreePoolAlignedWithTag(Instance, buffer, READ_BUFFER_TAG);
    if (FileObject != NULL)
        ObDereferenceObject(FileObject);
    return Status;
}