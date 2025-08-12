
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
    
    //ReadBuffer需要函数返回STATUS_SUCCESS后，调用者手动释放
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

    // 业务数据最大可读取范围：总大小 - 头部大小
    const LONGLONG MaxBusinessSize = FileSize - HEADER_SIZE;

    // 校验逻辑偏移是否超出业务数据范围
    if (ByteOffset.QuadPart >= MaxBusinessSize) {  // 注意：用原始逻辑偏移判断
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->End of business data.\n"));
        Status = STATUS_END_OF_FILE;
        goto EXIT;
    }
    // 限制读取长度不超过业务数据剩余范围
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

// 标识头读取函数
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
    LARGE_INTEGER ByteOffset = { 0 };  // 从文件头部（0偏移）读取

    // 读取标识头大小的数据（固定为结构体大小）
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

    // 拷贝并校验标识头
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

    // 头部大小
    const ULONG HEADER_SIZE = sizeof(POC_ENCRYPTION_HEADER);
    // 修正写入偏移：业务数据从HEADER_SIZE后开始
    LARGE_INTEGER actualOffset = ByteOffset;
    actualOffset.QuadPart += HEADER_SIZE;  // 核心修改：加上头部偏移

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
    // 头部大小
    const ULONG HEADER_SIZE = sizeof(POC_ENCRYPTION_HEADER);

    FileSize = PocQueryEndOfFileInfo(FltObjects->Instance, FltObjects->FileObject);

    // 若文件大小小于头部大小，视为未初始化
    if (FileSize < HEADER_SIZE) {
        Status = STATUS_END_OF_FILE;
        goto EXIT;
    }

    // 读取头部（偏移0，长度为头部大小）
    ByteOffset.QuadPart = 0;  // 核心修改：从文件起始位置读取头部

    Status = PocReadFileNoCache(
        FltObjects->Instance,
        FltObjects->Volume,
        StreamContext->FileName,
        ByteOffset,
        sizeof(POC_ENCRYPTION_HEADER),  // 只读取加密头大小
        &OutReadBuffer,
        &BytesRead);

    if (!NT_SUCCESS(Status) || NULL == OutReadBuffer || BytesRead != sizeof(POC_ENCRYPTION_HEADER))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReadFileNoCache failed. ProcessName = %ws Status = 0x%x\n", __FUNCTION__, ProcessName, Status));
        goto EXIT;
    }
    // 校验头部标识
    PPOC_ENCRYPTION_HEADER header = (PPOC_ENCRYPTION_HEADER)OutReadBuffer;
    // 校验加密头标识和文件名
    if (strncmp(((PPOC_ENCRYPTION_HEADER)OutReadBuffer)->Flag, EncryptionHeader.Flag,
        strlen(EncryptionHeader.Flag)) == 0 &&
        wcsncmp(((PPOC_ENCRYPTION_HEADER)OutReadBuffer)->FileName, StreamContext->FileName,
            POC_MAX_NAME_LENGTH) == 0)  // 用固定长度避免wcslen风险
    {

        /*
        * 驱动加载后，文件如果有缓冲或者被内存映射读写过，清一下缓冲，防止出现密文
        * 只要驱动加载之前有缓冲，都要清掉。
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

        // 更新流上下文（业务数据大小 = 总大小 - 头部大小）
        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
        if (0 == StreamContext->FileSize) {
            StreamContext->FileSize = header->FileSize;  // 或 FileSize - HEADER_SIZE
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
     * @brief 更新文件的加密头部信息（包含文件大小、加密状态、文件名等）
     * @param Volume 卷对象（用于获取卷上下文）
     * @param Instance 微筛选实例
     * @param StreamContext 文件流上下文（需包含FileName、HeaderSize等关键信息）
     * @return STATUS_SUCCESS 成功；其他状态码 失败（参数无效、文件操作失败等）
     */
    if (NULL == StreamContext || StreamContext->HeaderSize == 0 || NULL == StreamContext->FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->参数无效：StreamContext或HeaderSize或FileName为空\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PPOC_VOLUME_CONTEXT VolumeContext = NULL;
    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    const ULONG HEADER_SIZE = sizeof(POC_ENCRYPTION_HEADER);  // 加密头固定大小
    PCHAR WriteBuffer = NULL;
    ULONG BytesWritten = 0;

    // 获取卷上下文（校验扇区大小）
    Status = FltGetVolumeContext(gFilterHandle, Volume, &VolumeContext);
    if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->获取卷上下文失败，Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    // 初始化文件名和对象属性
    RtlInitUnicodeString(&uFileName, StreamContext->FileName);
    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 打开文件（仅用于写入加密头）
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
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->文件已删除，Status = 0x%x\n", __FUNCTION__, Status));
        }
        else
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->打开文件失败，Status = 0x%x\n", __FUNCTION__, Status));
        }
        goto EXIT;
    }

    // 分配加密头缓冲区（按扇区对齐）
    WriteBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, HEADER_SIZE, WRITE_BUFFER_TAG);
    if (NULL == WriteBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->分配缓冲区失败\n", __FUNCTION__));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }
    RtlZeroMemory(WriteBuffer, HEADER_SIZE);

    // 填充加密头数据（增强边界检查）
    RtlMoveMemory(WriteBuffer, &EncryptionHeader, HEADER_SIZE);
    ((PPOC_ENCRYPTION_HEADER)WriteBuffer)->FileSize = StreamContext->FileSize;
    ((PPOC_ENCRYPTION_HEADER)WriteBuffer)->IsCipherText = StreamContext->IsCipherText;

    // 限制文件名复制长度，避免越界（假设POC_MAX_NAME_LENGTH >= 实际文件名长度）
    ULONG copyNameLen = min(POC_MAX_NAME_LENGTH * sizeof(WCHAR), wcslen(StreamContext->FileName) * sizeof(WCHAR) + sizeof(WCHAR));
    RtlMoveMemory(((PPOC_ENCRYPTION_HEADER)WriteBuffer)->FileName, StreamContext->FileName, copyNameLen);

    // 写入加密头到文件起始位置（校验写入完整性）
    LARGE_INTEGER writeOffset = { 0 };  // 从文件开头写入
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->写入加密头失败，Status = 0x%x，实际写入 %d 字节\n", __FUNCTION__, Status, BytesWritten));
        goto EXIT;
    }

    // 提前关闭文件句柄（避免后续操作干扰）
    FltClose(hFile);
    hFile = NULL;
    ObDereferenceObject(FileObject);
    FileObject = NULL;

    // 处理影子节对象指针（缓存同步）
    if (NULL != StreamContext->ShadowSectionObjectPointers->DataSectionObject)
    {
        // 重新打开文件用于缓存操作
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
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->重新打开文件失败，Status = 0x%x\n", __FUNCTION__, Status));
            goto EXIT;
        }

        // 关联影子节对象
        FileObject->SectionObjectPointer = StreamContext->ShadowSectionObjectPointers;

        // 初始化缓存（如果需要）
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
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->初始化缓存失败，Status = 0x%x\n", __FUNCTION__, Status));
                goto EXIT;
            }
        }

        // 同步缓存大小
        if (CcIsFileCached(FileObject))
        {
            PFSRTL_ADVANCED_FCB_HEADER fcbHeader = (PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext;
            ExAcquireResourceExclusiveLite(fcbHeader->Resource, TRUE);

            // 更新缓存大小
            CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&fcbHeader->AllocationSize);
            CcPurgeCacheSection(StreamContext->ShadowSectionObjectPointers, NULL, 0, FALSE);

            ExReleaseResourceLite(fcbHeader->Resource);

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                ("%s->同步缓存大小完成：文件=%ws，分配大小=%I64d，有效数据长度=%I64d\n",
                    __FUNCTION__,
                    StreamContext->FileName,
                    fcbHeader->AllocationSize.QuadPart,
                    fcbHeader->ValidDataLength.QuadPart));
        }
    }

    // 更新上下文状态（加锁保护）
    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
    StreamContext->IsDirty = FALSE;
    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

    Status = STATUS_SUCCESS;

EXIT:
    // 资源清理（确保所有资源都被释放）
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
    * 这里不能用FltCreateFile，因为它建的FileObject是非重入的，在这个FileObject上建立的缓冲也是非重入的，
    * 我们的PreWrite无法加密后面PocWriteFileIntoCache写入的数据。
    * 如果一个大文件，在特权加密之前并没有建立缓冲，那么这里就会出现上述情况，特权加密实际上是失败的。
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
    * 这里不能用FltWriteFileEx，因为它的缓冲写是非重入的，16个字节以内的文件
    * 我们需要缓冲写操作重入到minifilter中去扩展文件大小。
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
            * PrivateCacheMap要置0，否则文件系统驱动不建立缓冲，不过这里不会进入了，
            * 因为在PostCreate对这个状态的文件，无论是什么进程，都指向明文缓冲。
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


VOID PocUpdateHeaderThread(IN PVOID StartContext)  // 已重命名，原名为 PocAppendEncTailerThread
{
    PPOC_STREAM_CONTEXT StreamContext = (PPOC_STREAM_CONTEXT)StartContext;
    if (NULL == StreamContext)
        return;

    // 确保在操作前获取资源锁，防止并发问题
    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

    // 注释：将原有写入尾标识的调用改为更新头标识
    NTSTATUS status = PocUpdateEncryptionHeader(
        StreamContext->Volume,
        StreamContext->Instance,
        StreamContext
    );

    if (NT_SUCCESS(status))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->标识头更新成功. File = %ws\n",
            __FUNCTION__, StreamContext->FileName));
    }
    else
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->标识头更新失败. File = %ws, Status = 0x%x\n",
            __FUNCTION__, StreamContext->FileName, status));
    }

    // 释放资源锁
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

// 新增：初始化标识头（文件创建时写入）
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
    LARGE_INTEGER ByteOffset = { 0 }; // 写入文件头部（0偏移）
    ULONG BytesWritten = 0;
    ULONG HeaderSize = sizeof(POC_ENCRYPTION_HEADER);

    // 获取卷信息（用于对齐）
    PFLT_VOLUME Volume = NULL;

    // 先通过实例获取卷（直接在调用处处理参数）
    Status = FltGetVolumeFromInstance(Instance, &Volume);
    if (!NT_SUCCESS(Status)) {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitEncryptionHeader->FltGetVolumeFromInstance failed: 0x%x\n", Status));
        goto EXIT;
    }

    // 再获取卷上下文
    Status = FltGetVolumeContext(gFilterHandle, Volume, &VolumeContext);
    if (!NT_SUCCESS(Status) || VolumeContext->SectorSize == 0) {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitEncryptionHeader->Get volume context failed: 0x%x\n", Status));
        goto EXIT;
    }

    // 分配对齐的缓冲区
    HeaderBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, HeaderSize, WRITE_BUFFER_TAG);
    if (NULL == HeaderBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitEncryptionHeader->Allocate buffer failed\n"));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }
    RtlZeroMemory(HeaderBuffer, HeaderSize);

    // 填充标识头固定信息
    strncpy_s(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->Flag, sizeof(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->Flag),
        "FOKS-TROT-HEADER", _TRUNCATE); // 固定标识
    wcsncpy_s(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->FileName, POC_MAX_NAME_LENGTH,
        FileName, _TRUNCATE); // 文件名
    ((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->HeaderSize = HeaderSize; // 标识头自身大小
    ((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->IsCipherText = FALSE; // 初始为未加密
    strncpy_s(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->EncryptionAlgorithmType,
        sizeof(((PPOC_ENCRYPTION_HEADER)HeaderBuffer)->EncryptionAlgorithmType),
        "AES-256", _TRUNCATE); // 默认算法

    // 写入标识头到文件
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

// 新增：向文件添加标识头（线程中调用）
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

    // 打开文件获取当前大小
    Status = PocInitFlushFileObject(StreamContext->FileName, &FileObject);
    if (!NT_SUCCESS(Status) || NULL == FileObject)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Open file failed: 0x%x\n", __FUNCTION__, Status));
        return Status;
    }

    // 读取现有头部（若存在）
    POC_ENCRYPTION_HEADER header = { 0 };
    LARGE_INTEGER offset = { 0 };
    PCHAR buffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, HEADER_SIZE, READ_BUFFER_TAG);
    if (NULL == buffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }

    // 读取当前头部
    Status = FltReadFileEx(Instance, FileObject, &offset, HEADER_SIZE, buffer, 0, NULL, NULL, NULL, NULL, NULL);
    if (NT_SUCCESS(Status))
    {
        RtlCopyMemory(&header, buffer, HEADER_SIZE);
    }
    else if (STATUS_END_OF_FILE == Status)
    {
        // 文件未初始化头部，使用默认值
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

    // 更新头部信息
    header.FileSize = StreamContext->FileSize;
    header.IsCipherText = StreamContext->IsCipherText;

    // 写回头部
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