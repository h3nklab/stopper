#pragma once

typedef struct _STOP_DATA
{
    LIST_ENTRY listEntry;
    unsigned char cMajor;
    unsigned char cMinor;
    BOOLEAN bPreOperation;
    PWCHAR pstrProcessName;
    PWCHAR pstrPathContain;
    LONG lPid;
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
    _In_ LONG lPid,
    _In_ LONG lCount,
    _In_ BOOLEAN bCrash);

NTSTATUS
OnGetStopperInfo(
    _In_ PVOID pReturnBuffer,
    _In_ ULONG ulBufferLength);

BOOLEAN
NeedStop(
    _In_ BOOLEAN bPreOperation,
    _In_ PFLT_CALLBACK_DATA pData);

VOID
RemoveStopEntry(
    _In_ PSTOP_DATA pStop);

NTSTATUS
HdevGetFileNameFromPath(
    _In_ POOL_TYPE poolType,
    _In_ PUNICODE_STRING pusPath,
    _Out_ PUNICODE_STRING pusParentPath,
    _Out_ PUNICODE_STRING pusFileName,
    _In_ BOOLEAN bCopyString);

VOID
HdevFreeUnicodeString(
    _Inout_ PUNICODE_STRING pusString);

NTSTATUS
HdevCopyUnicodeString(
    _In_ POOL_TYPE poolType,
    _Out_ PUNICODE_STRING pusDst,
    _In_ PCUNICODE_STRING pusSrc);