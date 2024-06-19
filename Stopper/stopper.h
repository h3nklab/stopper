#pragma once

#define ExclusiveLock KeAcquireSpinLockRaiseToDpc
#define ReleaseLock KeReleaseSpinLock

#define STOPPER_TAG 'TSDH'

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

extern ULONG gTraceFlags;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))


typedef
(*ZWQUERYINFORMATIONPROCESS) (
    _In_ HANDLE hProcessHandle,
    _In_ PROCESSINFOCLASS infoClass,
    _Out_ PVOID pProcessInformation,
    _In_ ULONG ulProcessInformationLength,
    _Out_opt_ PULONG pulReturnLength);

extern PFLT_FILTER ghFilter;
extern ZWQUERYINFORMATIONPROCESS fpZwQueryInformationProcess;

extern PLIST_ENTRY  gpListStopHead;
extern KSPIN_LOCK gStopLock;
extern CHAR gcEnabled;

BOOLEAN
IsEnabled();

VOID
EnableDriver(
    _In_ BOOLEAN bEnable);