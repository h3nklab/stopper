#pragma once

typedef struct _STOP_DATA
{
    LIST_ENTRY listEntry;
    unsigned char cMajor;
    unsigned char cMinor;
    BOOLEAN bPreOperation;
    PWCHAR pstrProcessName;
    PWCHAR pstrPathContain;
    HANDLE hPid;
    LONG lCount;
    BOOLEAN bCrash;
} STOP_DATA, *PSTOP_DATA;

NTSTATUS
GetProcessImageFile(
    _Out_ PWCHAR *pstrImageFile,
    _Out_ PWCHAR *pstrCommandLine);

NTSTATUS
GetFileNameFromPath(
    _In_ POOL_FLAGS flags,
    _In_ PCUNICODE_STRING pusPath,
    _Out_ PWCHAR *pusFileName);

NTSTATUS
GetStringFromUnicode(
    _In_ POOL_FLAGS flags,
    _In_ PCUNICODE_STRING pstrUnicode,
    _Out_ PWCHAR *pstrString);

VOID
OnClearStop(
    _In_ unsigned char cMajor,
    _In_ unsigned char cMinor,
    _In_ BOOLEAN bPreOperation);

NTSTATUS
OnCleanupStop(
    _Out_ LONG *plNumber);

NTSTATUS
OnGetStopperNumber(
    _Out_ LONG *plNumber);

NTSTATUS
OnAddStop(
    _In_ unsigned char cMajor,
    _In_ unsigned char cMinor,
    _In_ BOOLEAN bPreOperation,
    _In_ PWCHAR pstrProcessName,
    _In_ PWCHAR pstrPathContain,
    _In_ HANDLE hPid,
    _In_ LONG lCount,
    _In_ BOOLEAN bCrash);

BOOLEAN
NeedStop(
    _In_ unsigned char cMajor,
    _In_ unsigned char cMinor,
    _In_ BOOLEAN bPreOperation);

NTSTATUS
InitLock(
    _Inout_ PERESOURCE *pLock);

NTSTATUS
DeleteLock(
    _Inout_ PERESOURCE *pLock);

VOID
RemoveStopEntry(
    _In_ PSTOP_DATA pStop);