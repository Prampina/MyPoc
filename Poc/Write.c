#include "write.h"
#include "context.h"
#include "utils.h"
#include "cipher.h"
#include "filefuncs.h"
#include "process.h"


// ====== �������������� - ���ٸ��±�ʶͷ�е��ļ���С ======
// �����ļ������������������PocPreWriteOperation֮ǰ
NTSTATUS PocUpdateHeaderFileSize(
    IN PPOC_STREAM_CONTEXT StreamContext,
    IN LONGLONG NewFileSize)
{
    // ����У�飨��ֹ��ָ�����Чֵ��
    if (StreamContext == NULL || StreamContext->FlushFileObject == NULL || NewFileSize < 0)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->��Ч����\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }
    const LONGLONG FILE_SIZE_OFFSET_IN_HEADER = 16;
    
    // ���ƫ�����Ƿ��ڹ̶���ʶͷ��Χ�ڣ�ȷ����Խ�磩
    if (FILE_SIZE_OFFSET_IN_HEADER < 0 ||
        FILE_SIZE_OFFSET_IN_HEADER + sizeof(LONGLONG) > POC_HEADER_SIZE)  // POC_HEADER_SIZE����Ĺ̶���ʶͷ��С
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->�ļ���С�ֶ�ƫ�Ƴ�����ʶͷ��Χ\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    // ����д��ƫ��
    LARGE_INTEGER offset = { 0 };
    offset.QuadPart = FILE_SIZE_OFFSET_IN_HEADER;  // ֱ��ʹ�ù̶�ƫ��

    // ������ֹ�����޸ĳ�ͻ��ʹ���������ĵ���Դ����
    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

    // д�����ļ���С����ʶͷ
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = ZwWriteFile(
        StreamContext->FlushFileObject,  // ����д����ļ�����
        NULL,                            // ���ȴ��첽����
        NULL, NULL,                      // ��APC��������
        &ioStatus,
        &NewFileSize,                    // ��д����ļ���Сֵ
        sizeof(LONGLONG),                // �̶����ȣ�8�ֽڣ�
        &offset,                         // ��ʶͷ�ڵ�ƫ��
        NULL                             // ���ֽ�ƫ��ģʽ
    );

    // ͬ�������ڴ��е��ļ���С�������ڴ������һ�£�
    if (NT_SUCCESS(status))
    {
        StreamContext->FileSize = NewFileSize;
    }

    // �ͷ���
    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

    return status;
}

FLT_PREOP_CALLBACK_STATUS
PocPreWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    NTSTATUS Status;

    WCHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;

    BOOLEAN NonCachedIo = FALSE;
    BOOLEAN PagingIo = FALSE;

    PCHAR OrigBuffer = NULL, NewBuffer = NULL;
    PMDL NewMdl = NULL;
    LONGLONG NewBufferLength = 0;

    LONGLONG FileSize = 0, StartingVbo = 0, ByteCount = 0, LengthReturned = 0;
    LONGLONG AdjustedStartingVbo = 0;  // ����д��ƫ�ƣ��������ͷ

    PPOC_VOLUME_CONTEXT VolumeContext = NULL;
    ULONG SectorSize = 0;

    PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = NULL;

    ByteCount = Data->Iopb->Parameters.Write.Length;
    StartingVbo = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;

    NonCachedIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE);
    PagingIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO);


    if (FLT_IS_FASTIO_OPERATION(Data))
    {
        Status = FLT_PREOP_DISALLOW_FASTIO;
        goto ERROR;
    }

    if (0 == ByteCount)
    {
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto ERROR;
    }


    Status = PocFindOrCreateStreamContext(
        Data->Iopb->TargetInstance,
        Data->Iopb->TargetFileObject,
        FALSE,
        &StreamContext,
        &ContextCreated);

    if (STATUS_SUCCESS != Status)
    {
        if (STATUS_NOT_FOUND != Status && !FsRtlIsPagingFile(Data->Iopb->TargetFileObject))
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocFindOrCreateStreamContext failed. Status = 0x%x.\n",
                __FUNCTION__,
                Status));
        }
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto ERROR;
    }

    Status = PocGetProcessName(Data, ProcessName);


    if (PagingIo && 0 != StreamContext->WriteThroughFileSize)
    {
        FileSize = StreamContext->WriteThroughFileSize;
    }
    else
    {
        FileSize = ((PFSRTL_ADVANCED_FCB_HEADER)FltObjects->FileObject->FsContext)->FileSize.QuadPart;
    }


    // ����д��ƫ�ƣ��������ͷ
    AdjustedStartingVbo = StartingVbo + POC_HEADER_SIZE;
    Data->Iopb->Parameters.Write.ByteOffset.QuadPart = AdjustedStartingVbo;
    FltSetCallbackDataDirty(Data);  // ֪ͨƫ���޸�

    if (POC_RENAME_TO_ENCRYPT == StreamContext->Flag && NonCachedIo)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
            ("%s->Leave PostClose will encrypt the file. StartingVbo = %I64d Length = %I64d ProcessName = %ws File = %ws.\n",
                __FUNCTION__,
                Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
                ByteCount,
                ProcessName,
                StreamContext->FileName));

        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto ERROR;
    }


    if (FltObjects->FileObject->SectionObjectPointer ==
        StreamContext->ShadowSectionObjectPointers)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
            ("%s->Block NonCachedIo = %d chipertext cachemap StartingVbo = %I64d Length = %I64d ProcessName = %ws File = %ws.",
                __FUNCTION__,
                NonCachedIo ? 1 : 0,
                Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
                ByteCount,
                ProcessName,
                StreamContext->FileName));

        Data->IoStatus.Status = STATUS_SUCCESS;
        Data->IoStatus.Information = Data->Iopb->Parameters.Write.Length;

        Status = FLT_PREOP_COMPLETE;
        goto ERROR;
    }


    SwapBufferContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(POC_SWAP_BUFFER_CONTEXT), WRITE_BUFFER_TAG);

    if (NULL == SwapBufferContext)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreWriteOperation->ExAllocatePoolWithTag SwapBufferContext failed.\n"));
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        Status = FLT_PREOP_COMPLETE;
        goto ERROR;
    }

    RtlZeroMemory(SwapBufferContext, sizeof(POC_SWAP_BUFFER_CONTEXT));


    if (!NonCachedIo)
    {
        /*
        * �Ƴ�С�ļ��Զ���չ�߼���ʹ��ʵ��д���С
        */
        if (FlagOn(FltObjects->FileObject->Flags, FO_WRITE_THROUGH))
        {
            // ====== ���������ȸ��±�ʶͷ�е��ļ���С ======
        // ȷ����ʶͷ�ѳ�ʼ����StreamContext��Ч
            if (StreamContext != NULL && StreamContext->HeaderSize > 0 && StreamContext->FlushFileObject != NULL)
            {
                LONGLONG newFileSize = StartingVbo + Data->Iopb->Parameters.Write.Length;
                // �����´�С���ڵ�ǰ��¼ʱ���£�������Чд�룩
                if (newFileSize > StreamContext->FileSize)
                {
                    NTSTATUS updateStatus = PocUpdateHeaderFileSize(StreamContext, newFileSize);
                    if (!NT_SUCCESS(updateStatus))
                    {
                        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                            ("%s->WRITE_THROUGHʱ���±�ʶͷʧ��. Status = 0x%x\n",
                                __FUNCTION__, updateStatus));
                    }
                }
            }
            // ԭ���߼��������ļ���С��������
            StreamContext->WriteThroughFileSize = StartingVbo + Data->Iopb->Parameters.Write.Length;
        }
    }


    if (!PagingIo)
    {
        if (StartingVbo + ByteCount > FileSize)
        {
            SwapBufferContext->IsCacheExtend = TRUE;
        }
    }


    if (NonCachedIo)
    {
        Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &VolumeContext);

        if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->FltGetVolumeContext failed. Status = 0x%x\n", Status));
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            Status = FLT_PREOP_COMPLETE;
            goto ERROR;
        }

        SectorSize = VolumeContext->SectorSize;

        if (NULL != VolumeContext)
        {
            FltReleaseContext(VolumeContext);
            VolumeContext = NULL;
        }


        if (!PagingIo || FileSize >= StartingVbo + ByteCount)
        {
            LengthReturned = ByteCount;
        }
        else
        {
            LengthReturned = FileSize - StartingVbo;
        }

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreWriteOperation->RealToWrite = %I64d.\n", LengthReturned));

        if (Data->Iopb->Parameters.Write.MdlAddress != NULL)
        {

            FLT_ASSERT(((PMDL)Data->Iopb->Parameters.Write.MdlAddress)->Next == NULL);

            OrigBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress,
                NormalPagePriority | MdlMappingNoExecute);

            if (OrigBuffer == NULL)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreWriteOperation->Failed to get system address for MDL: %p\n",
                    Data->Iopb->Parameters.Write.MdlAddress));

                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_PREOP_COMPLETE;
                goto ERROR;
            }

        }
        else
        {
            OrigBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
        }



        if (FALSE == StreamContext->IsCipherText &&
            FileSize % SectorSize == 0 &&
            FileSize > PAGE_SIZE &&
            NonCachedIo)
        {
            if (StartingVbo <= FileSize - PAGE_SIZE &&
                StartingVbo + ByteCount >= FileSize - PAGE_SIZE + SectorSize)
            {
                if (strncmp(
                    ((PPOC_ENCRYPTION_HEADER)(OrigBuffer + FileSize - PAGE_SIZE - StartingVbo))->Flag,
                    EncryptionHeader.Flag,
                    strlen(EncryptionHeader.Flag)) == 0)
                {

                    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

                    StreamContext->IsReEncrypted = TRUE;

                    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                        ("%s->File has been repeatedly encrypted. StartingVbo = %I64d Length = %I64d ProcessName = %ws File = %ws.",
                            __FUNCTION__,
                            Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
                            ByteCount,
                            ProcessName,
                            StreamContext->FileName));

                }
            }
        }


        // ʹ��ʵ�ʴ�С���仺��������ǿ����չ
        NewBufferLength = ByteCount;

        NewBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, NewBufferLength, WRITE_BUFFER_TAG);

        if (NULL == NewBuffer)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreWriteOperation->FltAllocatePoolAlignedWithTag NewBuffer failed.\n"));
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            Status = FLT_PREOP_COMPLETE;
            goto ERROR;
        }

        RtlZeroMemory(NewBuffer, NewBufferLength);

        if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
        {

            NewMdl = IoAllocateMdl(NewBuffer, (ULONG)NewBufferLength, FALSE, FALSE, NULL);

            if (NewMdl == NULL)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreWriteOperation->IoAllocateMdl NewMdl failed.\n"));
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_PREOP_COMPLETE;
                goto ERROR;
            }

            MmBuildMdlForNonPagedPool(NewMdl);
        }



        try
        {
            // ����ʵ�����ݳ���ѡ����ܷ�ʽ����ǿ����չС�ļ�
            if (LengthReturned % AES_BLOCK_SIZE != 0)
            {
                Status = PocAesECBEncrypt_CiphertextStealing(
                    OrigBuffer,
                    (ULONG)LengthReturned,
                    NewBuffer);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreWriteOperation->PocAesECBEncrypt_CiphertextStealing failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    Status = FLT_PREOP_COMPLETE;
                    goto ERROR;
                }
            }
            else
            {
                Status = PocAesECBEncrypt(
                    OrigBuffer,
                    (ULONG)LengthReturned,
                    NewBuffer,
                    &(ULONG)LengthReturned);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreWriteOperation->PocAesECBEncrypt failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    Status = FLT_PREOP_COMPLETE;
                    goto ERROR;
                }
            }

        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {
            Data->IoStatus.Status = GetExceptionCode();
            Data->IoStatus.Information = 0;
            Status = FLT_PREOP_COMPLETE;
            goto ERROR;
        }




        SwapBufferContext->NewBuffer = NewBuffer;
        SwapBufferContext->NewMdl = NewMdl;
        SwapBufferContext->StreamContext = StreamContext;
        *CompletionContext = SwapBufferContext;

        Data->Iopb->Parameters.Write.WriteBuffer = NewBuffer;
        Data->Iopb->Parameters.Write.MdlAddress = NewMdl;
        FltSetCallbackDataDirty(Data);


        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreWriteOperation->Encrypt success. StartingVbo = %I64d Length = %d ProcessName = %ws File = %ws.\n\n",
            Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
            (ULONG)LengthReturned,
            ProcessName,
            StreamContext->FileName));


        Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        goto EXIT;
    }



    *CompletionContext = SwapBufferContext;
    SwapBufferContext->StreamContext = StreamContext;
    Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    goto EXIT;

ERROR:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (NULL != NewBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, NewBuffer, WRITE_BUFFER_TAG);
        NewBuffer = NULL;
    }

    if (NULL != NewMdl)
    {
        IoFreeMdl(NewMdl);
        NewMdl = NULL;
    }

    if (NULL != SwapBufferContext)
    {
        ExFreePoolWithTag(SwapBufferContext, WRITE_BUFFER_TAG);
        SwapBufferContext = NULL;
    }

EXIT:

    return Status;
}


FLT_POSTOP_CALLBACK_STATUS
PocPostWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);


    ASSERT(CompletionContext != NULL);
    ASSERT(((PPOC_SWAP_BUFFER_CONTEXT)CompletionContext)->StreamContext != NULL);

    PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = NULL;
    PPOC_STREAM_CONTEXT StreamContext = NULL;

    LONGLONG FileSize = 0;
    NTSTATUS HeaderUpdateStatus = STATUS_SUCCESS;  // ���ͷ����״̬

    SwapBufferContext = CompletionContext;
    StreamContext = SwapBufferContext->StreamContext;


    if (0 != StreamContext->WriteThroughFileSize)
    {
        FileSize = StreamContext->WriteThroughFileSize;
    }
    else
    {
        FileSize = ((PFSRTL_ADVANCED_FCB_HEADER)FltObjects->FileObject->FsContext)->FileSize.QuadPart;
    }


    if (BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE))
    {
        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
        StreamContext->IsDirty = TRUE;
        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
    }

    if (!BooleanFlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) &&
        FileSize <= AES_BLOCK_SIZE)
    {
        FltObjects->FileObject->CurrentByteOffset.QuadPart = StreamContext->FileSize;
    }

    if (BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE) &&
        (TRUE != StreamContext->LessThanAesBlockSize ||
            FileSize > AES_BLOCK_SIZE))
    {
        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
        StreamContext->FileSize = FileSize;
        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
    }


    if (TRUE == SwapBufferContext->IsCacheExtend &&
        NULL != StreamContext->ShadowSectionObjectPointers &&
        NULL != StreamContext->ShadowSectionObjectPointers->SharedCacheMap &&
        NULL != StreamContext->ShadowFileObject)
    {
        ExAcquireResourceExclusiveLite(((PFSRTL_ADVANCED_FCB_HEADER)(FltObjects->FileObject->FsContext))->Resource, TRUE);

        CcSetFileSizes(StreamContext->ShadowFileObject,
            (PCC_FILE_SIZES) & ((PFSRTL_ADVANCED_FCB_HEADER)(FltObjects->FileObject->FsContext))->AllocationSize);

        ExReleaseResourceLite(((PFSRTL_ADVANCED_FCB_HEADER)(FltObjects->FileObject->FsContext))->Resource);
    }


    if (0 != SwapBufferContext->OriginalLength)
    {
        Data->IoStatus.Information = SwapBufferContext->OriginalLength;
    }


    if (Data->Iopb->Parameters.Write.ByteOffset.QuadPart +
        Data->Iopb->Parameters.Write.Length >=
        FileSize + POC_HEADER_SIZE  // ����ԭ���ͷ��С�ж�ʵ���ļ�β
        && BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE))
    {
        // ʵʱ����β�����ͷ
        if (TRUE == StreamContext->IsReEncrypted)
        {
            PocUpdateFlagInStreamContext(StreamContext, POC_TO_DECRYPT_FILE);
            HeaderUpdateStatus = PocUpdateEncryptionHeader(
                FltObjects->Instance,
                FltObjects->FileObject,
                StreamContext
            );
        }
        else
        {
            PocUpdateFlagInStreamContext(StreamContext, POC_TO_APPEND_ENCRYPTION_HEADER);
            HeaderUpdateStatus = PocUpdateEncryptionHeader(
                FltObjects->Instance,
                FltObjects->FileObject,
                StreamContext
            );
        }


        if (!NT_SUCCESS(HeaderUpdateStatus))
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                ("%s->Failed to update encryption header. Status=0x%x\n",
                    __FUNCTION__, HeaderUpdateStatus));
        }

        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
        StreamContext->IsCipherText = TRUE;
        StreamContext->LessThanAesBlockSize = FALSE;
        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

        if (NULL != StreamContext->FlushFileObject)
        {
            ObDereferenceObject(StreamContext->FlushFileObject);
            StreamContext->FlushFileObject = NULL;
        }
    }


    if (FlagOn(FltObjects->FileObject->Flags, FO_WRITE_THROUGH))
    {
        StreamContext->WriteThroughFileSize = 0;
    }


    if (NULL != SwapBufferContext->NewBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, SwapBufferContext->NewBuffer, WRITE_BUFFER_TAG);
        SwapBufferContext->NewBuffer = NULL;
    }

    if (NULL != SwapBufferContext)
    {
        ExFreePoolWithTag(SwapBufferContext, WRITE_BUFFER_TAG);
        SwapBufferContext = NULL;
    }

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}