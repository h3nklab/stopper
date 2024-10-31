#pragma once

#define STOPPER_TAG                     'TSDH'
#define STOPPER_SEPARATOR               L'\\'

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

extern ULONG gTraceFlags;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

typedef struct _STOPPER_FILE_CONTEXT
{
    UNICODE_STRING usFileName;
} STOPPER_FILE_CONTEXT, *PSTOPPER_FILE_CONTEXT;

typedef
(*ZWQUERYINFORMATIONPROCESS) (
    _In_ HANDLE hProcessHandle,
    _In_ PROCESSINFOCLASS infoClass,
    _Out_ PVOID pProcessInformation,
    _In_ ULONG ulProcessInformationLength,
    _Out_opt_ PULONG pulReturnLength);

extern PFLT_FILTER gpFilter;
extern ZWQUERYINFORMATIONPROCESS fpZwQueryInformationProcess;

extern PLIST_ENTRY  gpListStopHead;
extern CHAR gcEnabled;

VOID
CleanupFileContext(
    _In_ PFLT_CONTEXT pContext,
    _In_ FLT_CONTEXT_TYPE contextType);

BOOLEAN
IsEnabled();

VOID
EnableDriver(
    _In_ BOOLEAN bEnable);

NTSTATUS
InitLock();

VOID
ExclusiveLock();

VOID
ReleaseLock();