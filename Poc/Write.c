
#include "write.h"
#include "context.h"
#include "utils.h"
#include "cipher.h"
#include "filefuncs.h"
#include "process.h"

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
    LONGLONG AdjustedStartingVbo = 0;  // 调整后的写入偏移（跳过标识头）

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
            /*
            * 说明不是目标扩展文件，在Create中没有创建StreamContext，不认为是个错误
            * 或者是一个Paging file，这里会返回0xc00000bb，
            * 原因是Fcb->Header.Flags2, FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS被清掉了
            *
            //
            //  To make FAT match the present functionality of NTFS, disable
            //  stream contexts on paging files
            //

            if (IsPagingFile) {
                SetFlag( Fcb->Header.Flags2, FSRTL_FLAG2_IS_PAGING_FILE );
                ClearFlag( Fcb->Header.Flags2, FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS );
            }
            */
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


    //PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
    //    ("\nPocPreWriteOperation->enter StartingVbo = %I64d Length = %d FileSize = %I64d ProcessName = %ws File = %ws.\n NonCachedIo = %d PagingIo = %d\n",
    //    Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
    //    Data->Iopb->Parameters.Write.Length,
    //    FileSize,
    //    ProcessName, StreamContext->FileName,
    //    NonCachedIo,
    //    PagingIo));

    // 关键修改1：调整写入偏移（跳过标识头区域）
    // 实际文件布局：[标识头(POC_HEADER_SIZE)][数据区]
    // 用户写入的逻辑偏移0对应实际文件的POC_HEADER_SIZE偏移
    AdjustedStartingVbo = StartingVbo + POC_HEADER_SIZE;
    Data->Iopb->Parameters.Write.ByteOffset.QuadPart = AdjustedStartingVbo;
    FltSetCallbackDataDirty(Data);  // 标记偏移修改

    if (POC_RENAME_TO_ENCRYPT == StreamContext->Flag && NonCachedIo)
    {
        /*
        * 未加密的doc,docx,ppt,pptx,xls,xlsx文件，进程直接写入这类文件时不会自动加密，
        * 而是会在该进程关闭以后，我们去判断是否应该加密该类文件。
        */
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
        /*
        * 不允许写入密文缓冲，尤其是NonCachedIo，会有死锁
        */
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
        // 关键修改2：删除小文件扩展逻辑（不再扩展至16字节对齐）
        // 改为直接记录原始大小（通过标识头存储，无需扩展文件）
        if (StartingVbo + Data->Iopb->Parameters.Write.Length > StreamContext->FileSize)
        {
            ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);
            // 记录实际写入后的文件大小（不含标识头）
            StreamContext->FileSize = StartingVbo + Data->Iopb->Parameters.Write.Length;
            StreamContext->LessThanAesBlockSize = (StreamContext->FileSize < AES_BLOCK_SIZE);
            ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
        }

        /*
        * 在CachedIo WRITE_THROUGH时暂存，在PagingIo时取出，替换Fcb->FileSize
        */
        if (FlagOn(FltObjects->FileObject->Flags, FO_WRITE_THROUGH))
        {
            StreamContext->WriteThroughFileSize = StartingVbo + Data->Iopb->Parameters.Write.Length;
        }
    }


    if (!PagingIo)
    {
        /*
        * 需要在PostWrite修改密文缓冲的大小
        */
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


        //LengthReturned是本次Write真正需要写的数据
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
            /*
            * 表明文件被重复加密了
            */
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


        


        if (FileSize > AES_BLOCK_SIZE &&
            LengthReturned < AES_BLOCK_SIZE)
        {
            NewBufferLength = SectorSize + ByteCount;
        }
        else
        {
            NewBufferLength = ByteCount;
        }

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
            // 关键修改3：删除小文件强制扩展加密逻辑，使用实际大小加密
            if (LengthReturned % AES_BLOCK_SIZE != 0 && FileSize > AES_BLOCK_SIZE)
            {
                /*
                * 当需要写的数据大于一个块时，且和块大小不对齐时，用密文挪用
                */
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
                /*
                * 对所有大小数据直接加密（包括小文件，不再强制扩展）
                */
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
    NTSTATUS HeaderUpdateStatus = STATUS_SUCCESS;  // 标识头更新状态

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
        /*
        * 文件被修改过，且还未写入文件标识尾，阻止备份进程读文件
        */
        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

        StreamContext->IsDirty = TRUE;

        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
    }

    if (!BooleanFlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) &&
        FileSize <= AES_BLOCK_SIZE)
    {
        /*
        * WriteFile之类的函数，
        * This function writes data to a file, starting at the position indicated by the file pointer. 
        * After the write operation has been completed, 
        * the file pointer is adjusted by the number of bytes written.
        */
        FltObjects->FileObject->CurrentByteOffset.QuadPart = StreamContext->FileSize;
    }

    if (BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE) &&
        (TRUE != StreamContext->LessThanAesBlockSize || 
            FileSize > AES_BLOCK_SIZE))
    {
        /*
        * 记录文件的明文大小，小于16个字节的StreamContext->FileSize已经在其他处更新过了，
        * 这里不能再更新了，因为这里的FileSize已经是16个字节了。
        */
        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

        StreamContext->FileSize = FileSize;

        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
    }

    
    /*
    * 扩展密文缓冲的大小，在PostWrite是因为，我们需要它进入文件系统驱动的Write去扩展AllocationSize等值，
    * 等这些值扩展以后，我们才能增大密文缓冲的大小。
    */
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
        /*
        * 写入长度被修改过，将它还原
        */
        Data->IoStatus.Information = SwapBufferContext->OriginalLength;
    }


    if (Data->Iopb->Parameters.Write.ByteOffset.QuadPart +
        Data->Iopb->Parameters.Write.Length >=
        FileSize + POC_HEADER_SIZE  // 加上标识头大小判断实际文件尾
        && BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE))
    {
        // 关键修改4：实时更新标识头（替代原标识尾逻辑）
        if (TRUE == StreamContext->IsReEncrypted)
        {
            PocUpdateFlagInStreamContext(StreamContext, POC_TO_DECRYPT_FILE);
            // 更新标识头加密状态为未加密
            HeaderUpdateStatus = PocUpdateEncryptionHeader(
                FltObjects->Instance,
                FltObjects->FileObject,
                StreamContext,
                FALSE  // 未加密
            );
        }
        else
        {
            PocUpdateFlagInStreamContext(StreamContext, POC_TO_APPEND_ENCRYPTION_HEADER);
            // 更新标识头加密状态为已加密，并记录文件大小
            HeaderUpdateStatus = PocUpdateEncryptionHeader(
                FltObjects->Instance,
                FltObjects->FileObject,
                StreamContext,
                TRUE  // 已加密
            );
        }


        if (!NT_SUCCESS(HeaderUpdateStatus))
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                ("%s->Failed to update encryption header. Status=0x%x\n",
                    __FUNCTION__, HeaderUpdateStatus));
        }

        /*
        * 表明文件已被加密，这样Read才会解密
        */
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
