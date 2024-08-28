/*++

Module Name:

    Stopper.c

Abstract:

    This is the main module of the Stopper miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>

#include "share.h"
#include "stopper.h"
#include "mem.h"
#include "features.h"
#include "comm.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PLIST_ENTRY gpListStopHead = NULL;
PERESOURCE  gpStopLock = NULL;
CHAR        gcEnabled = 1;

PFLT_FILTER ghFilter = NULL;
ULONG_PTR   OperationStatusCtx = 1;
PFLT_PORT gCommPort = NULL;
ULONG gTraceFlags = 1;

ZWQUERYINFORMATIONPROCESS fpZwQueryInformationProcess = NULL;

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
StopperInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
StopperInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
StopperInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
StopperUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
StopperInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
StopperPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
StopperOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
StopperPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
StopperPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
StopperDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, StopperUnload)
#pragma alloc_text(PAGE, StopperInstanceQueryTeardown)
#pragma alloc_text(PAGE, StopperInstanceSetup)
#pragma alloc_text(PAGE, StopperInstanceTeardownStart)
#pragma alloc_text(PAGE, StopperInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_CLOSE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_READ,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_WRITE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_SET_EA,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      StopperPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_PNP,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      StopperPreOperation,
      StopperPostOperation },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),        //  Size
    FLT_REGISTRATION_VERSION,          //  Version
    0,                                 //  Flags

    NULL,                              //  Context
    Callbacks,                         //  Operation callbacks

    StopperUnload,                     //  MiniFilterUnload

    StopperInstanceSetup,              //  InstanceSetup
    StopperInstanceQueryTeardown,      //  InstanceQueryTeardown
    StopperInstanceTeardownStart,      //  InstanceTeardownStart
    StopperInstanceTeardownComplete,   //  InstanceTeardownComplete

    NULL,                              //  GenerateFileName
    NULL,                              //  GenerateDestinationFileName
    NULL                               //  NormalizeNameComponent

};



/*  Return Value :

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
NTSTATUS
StopperInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!StopperInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
StopperInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!StopperInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
StopperInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!StopperInstanceTeardownStart: Entered\n") );
}


VOID
StopperInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!StopperInstanceTeardownComplete: Entered\n") );
}

BOOLEAN
IsEnabled()
{
    return (gcEnabled == 1);
}

VOID
EnableDriver(
    _In_ BOOLEAN bEnable)
{
    CHAR cEnable = bEnable ? 1 : 0;
    InterlockedExchange8(&gcEnabled, cEnable);
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING usConnectionPort = {0};
    UNICODE_STRING usRoutineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
    OBJECT_ATTRIBUTES oa = {0};
    PSECURITY_DESCRIPTOR pLogPortSD = NULL;
    PSECURITY_DESCRIPTOR pSecuredSD = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!DriverEntry: Entered\n") );

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Driver entry.......\n"));

    gpListStopHead = (PLIST_ENTRY) AllocateMemory(POOL_FLAG_NON_PAGED,
                                                  sizeof(LIST_ENTRY),
                                                  STOPPER_TAG);
    InitializeListHead(gpListStopHead);

    status = InitLock();
    if (NT_SUCCESS(status) == FALSE)
    {
        return status;
    }

    fpZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS) MmGetSystemRoutineAddress(&usRoutineName);
    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &ghFilter);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status) == FALSE)
    {
        goto Cleanup;
    }

    pLogPortSD = AllocateMemory(POOL_FLAG_NON_PAGED,
                                sizeof(SECURITY_DESCRIPTOR),
                                STOPPER_TAG);

    if (pLogPortSD == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    status = RtlCreateSecurityDescriptor(pLogPortSD,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(status) == FALSE)
    {
        goto Cleanup;
    }

    status = RtlSetDaclSecurityDescriptor(pLogPortSD,
                                          TRUE,
                                          NULL,
                                          FALSE);
    if (NT_SUCCESS(status) == FALSE)
    {
        goto Cleanup;
    }

    status = FltBuildDefaultSecurityDescriptor(&pSecuredSD, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status) == FALSE)
    {
        goto Cleanup;
    }

    RtlInitUnicodeString(&usConnectionPort, CONNECTION_PORT_NAME);
    InitializeObjectAttributes(&oa,
                               &usConnectionPort,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               pSecuredSD);

    status = FltCreateCommunicationPort(ghFilter,
                                        &gCommPort,
                                        &oa,
                                        NULL,
                                        StopperConnect,
                                        StopperDisconnect,
                                        StopperMessage,
                                        STOPPER_MAX_CONNECTION);
    if (NT_SUCCESS(status) == FALSE)
    {
        goto Cleanup;
    }
    //
    //  Start filtering i/o
    //

    status = FltStartFiltering(ghFilter);

    if (!NT_SUCCESS(status))
    {

        FltUnregisterFilter(ghFilter);
    }

Cleanup:
    FreeMemory(pLogPortSD);
    if (pSecuredSD != NULL)
    {
        FltFreeSecurityDescriptor(pSecuredSD);
    }
    return status;
}

NTSTATUS
StopperUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    PLIST_ENTRY pEntry = NULL;

    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!StopperUnload: Entered\n") );

    if (gCommPort != NULL)
    {
        FltCloseCommunicationPort(gCommPort);
        gCommPort = NULL;
    }

    EnableDriver(FALSE);

    ExclusiveLock();
    if (gpListStopHead != NULL)
    {
        while (IsListEmpty(gpListStopHead) == FALSE)
        {
            pEntry = RemoveHeadList(gpListStopHead);
            if (pEntry != NULL)
            {
                FreeMemory(pEntry);
            }
        }

        FreeMemory(gpListStopHead);
        gpListStopHead = NULL;
    }

    ReleaseLock();

    FltUnregisterFilter(ghFilter);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
StopperPreOperation (
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!StopperPreOperation: Entered\n") );

    if (IsEnabled() == FALSE)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (TRUE == NeedStop(TRUE, pData))
    {
        __debugbreak();
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
StopperOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!StopperOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("Stopper!StopperOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
StopperPostOperation (
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pCompletionContext);
    UNREFERENCED_PARAMETER(flags);

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!StopperPostOperation: Entered\n") );

    if (IsEnabled() == FALSE)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (TRUE == NeedStop(FALSE, pData))
    {
        __debugbreak();
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
StopperPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Stopper!StopperPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
StopperDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}


NTSTATUS
InitLock()
{
    NTSTATUS status = STATUS_SUCCESS;

    gpStopLock = (PERESOURCE) AllocateMemory(POOL_FLAG_NON_PAGED,
                                             sizeof(ERESOURCE),
                                             STOPPER_TAG);
    status = ExInitializeResourceLite(gpStopLock);

    if (NT_SUCCESS(status) == FALSE)
    {
        FreeMemory(gpStopLock);
        gpStopLock = NULL;
    }

    return status;
}

VOID
ExclusiveLock()
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gpStopLock == NULL)
    {
        status = InitLock();
        if (NT_SUCCESS(status) == FALSE)
        {
            return;
        }
    }
    ExAcquireResourceExclusiveLite(gpStopLock, TRUE);
}

VOID
ReleaseLock()
{
    ExReleaseResourceLite(gpStopLock);
}