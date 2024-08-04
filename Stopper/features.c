#include <fltKernel.h>
#include <dontuse.h>

#include "share.h"
#include "stopper.h"
#include "mem.h"
#include "features.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, GetProcessImageFile)
#pragma alloc_text(PAGE, NeedStop)
#endif

NTSTATUS
GetStringFromUnicode(
    _In_ POOL_FLAGS flags,
    _In_ PCUNICODE_STRING pstrUnicode,
    _Out_ PWCHAR *pstrString)
{
    NTSTATUS status = STATUS_SUCCESS;

    FLT_ASSERT(pstrString);
    FLT_ASSERT(pstrUnicode);

    *pstrString = (PWCHAR) AllocateMemory(flags,
                                          pstrUnicode->Length + sizeof(WCHAR),
                                          STOPPER_TAG);
    if (*pstrString != NULL)
    {
        RtlCopyMemory(*pstrString, pstrUnicode->Buffer, pstrUnicode->Length);
    }
    else
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    return status;
}

NTSTATUS
GetFileNameFromPath(
    _In_ POOL_FLAGS flags,
    _In_ PCUNICODE_STRING pusPath,
    _Out_ PWCHAR *pusFileName)
{
    NTSTATUS status = STATUS_SUCCESS;
    PWCHAR pwPtr = NULL;
    SIZE_T size = 0;

    FLT_ASSERT(pusPath);
    FLT_ASSERT(pusFileName);

    *pusFileName = NULL;

    pwPtr = pusPath->Buffer;
    pwPtr += (pusPath->Length / sizeof(WCHAR));
    pwPtr--;

    while ((*pwPtr != L'\\') && ((size * sizeof(WCHAR)) <= pusPath->Length))
    {
        size++;
        pwPtr--;
    }

    if (size > 0)
    {
        *pusFileName = (PWCHAR) AllocateMemory(flags,
                                               size * sizeof(WCHAR),
                                               STOPPER_TAG);
        if (*pusFileName == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
        pwPtr++;
        RtlCopyMemory(*pusFileName, pwPtr, size * sizeof(WCHAR));
    }

Cleanup:
    return status;
}

NTSTATUS
GetProcessImageFile(
    _Out_ PWCHAR *pstrImageFile,
    _Out_ PWCHAR *pstrCommandLine)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ulLength = 0;
    ULONG ulReturnedLength = 0;
    PVOID pBuffer = NULL;
    PUNICODE_STRING pusFullPath = NULL;
    HANDLE hCurrentProcess = NULL;

    FLT_ASSERT(pstrImageFile);
    FLT_ASSERT(pstrCommandLine);

    PAGED_CODE()

    *pstrImageFile = NULL;
    *pstrCommandLine = NULL;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    if (fpZwQueryInformationProcess == NULL)
    {
        status = STATUS_INVALID_ADDRESS;
        goto Cleanup;
    }

    do
    {
        ulLength = ulReturnedLength;
        if (ulLength > 0)
        {
            FreeMemory(pBuffer);
            pBuffer = AllocateMemory(POOL_FLAG_NON_PAGED,
                                     ulLength,
                                     STOPPER_TAG);
        }

        hCurrentProcess = ZwCurrentProcess();
        if (hCurrentProcess != NULL)
        {
            status = fpZwQueryInformationProcess(hCurrentProcess,
                                                 ProcessImageFileName,
                                                 pBuffer,
                                                 ulLength,
                                                 &ulReturnedLength);
        }
        else
        {
            status = STATUS_INVALID_HANDLE;
            goto Cleanup;
        }
    } while ((status == STATUS_INFO_LENGTH_MISMATCH) || (ulLength < ulReturnedLength));

    if (ulReturnedLength - (ULONG) sizeof(UNICODE_STRING) == 0)
    {
        return status;
    }

    pusFullPath = (PUNICODE_STRING) pBuffer;
    pBuffer = NULL;

    status = GetFileNameFromPath(POOL_FLAG_NON_PAGED, 
                                 pusFullPath,
                                 pstrImageFile);
    if (NT_SUCCESS(status) == FALSE)
    {
        goto Cleanup;
    }

    status = GetStringFromUnicode(POOL_FLAG_NON_PAGED, pusFullPath, pstrCommandLine);

Cleanup:
    if (NT_SUCCESS(status) == FALSE)
    {
        FreeMemory(*pstrImageFile);
        *pstrImageFile = NULL;

        FreeMemory(*pstrCommandLine);
        *pstrCommandLine = NULL;
    }
    FreeMemory(pusFullPath);
    return status;
}

BOOLEAN
NeedStop(
    _In_ BOOLEAN bPreOperation,
    _In_ PFLT_CALLBACK_DATA pData)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLIST_ENTRY pEntry = NULL;
    PLIST_ENTRY pRemoveEntry = NULL;
    PSTOP_DATA pStop = NULL;
    BOOLEAN bReturn = FALSE;
    PWCHAR pstrProcessName = NULL;
    PWCHAR pstrCommandLine = NULL;
    PWCHAR pstrPath = NULL;
    BOOLEAN bCrash = FALSE;
    KIRQL oldIrql;
    HANDLE hPid;

    PAGED_CODE();

    if (IsEnabled() == FALSE)
    {
        return FALSE;
    }

    FLT_ASSERT(gStopLock);
    FLT_ASSERT(gpListStopHead);

    status = GetProcessImageFile(&pstrProcessName, &pstrCommandLine);
    if ((NT_SUCCESS(status) == FALSE) || (pstrProcessName == NULL))
    {
        return FALSE;
    }

    if (_wcsicmp(pstrProcessName, L"stpcmd.exe") == 0)
    {
        return FALSE;
    }

    oldIrql = ExclusiveLock(&gStopLock);

    pEntry = gpListStopHead->Flink;
    while ((pEntry != gpListStopHead) && (bReturn == FALSE))
    {
        bReturn = TRUE;

        pStop = CONTAINING_RECORD(pEntry, STOP_DATA, listEntry);

        if (pStop->bPreOperation != bPreOperation)
        {
            bReturn = FALSE;
            pEntry = pEntry->Flink;
            continue;
        }

        if (pStop->cMajor != IRP_NONE)
        {
            if (pStop->cMajor != pData->Iopb->MajorFunction)
            {
                bReturn = FALSE;
                pEntry = pEntry->Flink;
                continue;
            }
        }

        if (pStop->cMinor != IRP_NONE)
        {
            if (pStop->cMinor != pData->Iopb->MinorFunction)
            {
                bReturn = FALSE;
                pEntry = pEntry->Flink;
                continue;
            }
        }

        if (pStop->pstrProcessName != NULL)
        {
            if (_wcsicmp(pstrProcessName, pStop->pstrProcessName) != 0)
            {
                bReturn = FALSE;
                pEntry = pEntry->Flink;
                continue;
            }
        }

        if (pStop->pstrPathContain != NULL)
        {
            FreeMemory(pstrPath);
            pstrPath = AllocateMemory(POOL_FLAG_NON_PAGED,
                                      pData->Iopb->TargetFileObject->FileName.Length + sizeof(WCHAR),
                                      STOPPER_TAG);
            if (pstrPath == NULL)
            {
                bReturn = FALSE;
                goto Cleanup;
            }

            RtlCopyMemory(pstrPath,
                          pData->Iopb->TargetFileObject->FileName.Buffer,
                          pData->Iopb->TargetFileObject->FileName.Length);

            if (wcsstr(pstrPath, pStop->pstrPathContain) == NULL)
            {
                bReturn = FALSE;
                pEntry = pEntry->Flink;
                continue;
            }
        }

        if (pStop->lPid != 0)
        {
            hPid = PsGetCurrentProcessId();
            if (RtlCompareMemory(&pStop->lPid, &hPid, sizeof(LONG)) == 0)
            {
                bReturn = FALSE;
                pEntry = pEntry->Flink;
                continue;
            }
        }

        if (bReturn == TRUE)
        {
            pStop->lCount--;
            if (pStop->lCount == 0)
            {
                pRemoveEntry = pEntry;
            }

            break;
        }

        bReturn = FALSE;
        pEntry = pEntry->Flink;
    }

    if (pRemoveEntry != NULL)
    {
        pStop = CONTAINING_RECORD(pRemoveEntry, STOP_DATA, listEntry);
        RemoveStopEntry(pStop);
        RemoveEntryList(pRemoveEntry);
        FreeMemory(pRemoveEntry);
    }

Cleanup:
    FreeMemory(pstrProcessName);
    FreeMemory(pstrPath);
    FreeMemory(pstrCommandLine);

    ReleaseLock(&gStopLock, oldIrql);

    if (bReturn == TRUE && bCrash == TRUE)
    {
        KeBugCheck(MANUALLY_INITIATED_CRASH1);
    }
    return bReturn;
}


NTSTATUS
OnGetStopperInfo(
    _In_ PVOID pReturnBuffer,
    _In_ ULONG ulBufferLength)
{
    PSTOP_DATA pStop = NULL;
    PLIST_ENTRY pEntry = NULL;
    KIRQL oldIrql;
    PGET_STOP_INFO_REPLY pReply = (PGET_STOP_INFO_REPLY) pReturnBuffer;
    ULONG ulLength;

    pReply->ulCount = 0;
    ulLength = sizeof(pReply->ulCount);

    oldIrql = ExclusiveLock(&gStopLock);

    pEntry = gpListStopHead->Flink;
    while ((pEntry != gpListStopHead) && (ulLength < ulBufferLength))
    {
        pStop = CONTAINING_RECORD(pEntry, STOP_DATA, listEntry);
        pReply->stop[pReply->ulCount].cMajor = pStop->cMajor;
        pReply->stop[pReply->ulCount].cMinor = pStop->cMinor;
        pReply->stop[pReply->ulCount].cCrash = pStop->bCrash;
        pReply->stop[pReply->ulCount].cPreOperation = pStop->bPreOperation;
        pReply->stop[pReply->ulCount].lCount = pStop->lCount;
        pReply->stop[pReply->ulCount].lPid = pStop->lPid;
        wcscpy_s(pReply->stop[pReply->ulCount].strPathContain,
                 sizeof(pReply->stop[pReply->ulCount]) / sizeof(WCHAR),
                 pStop->pstrPathContain);
        wcscpy_s(pReply->stop[pReply->ulCount].strProcessName,
                 sizeof(pReply->stop[pReply->ulCount].strProcessName) / sizeof(WCHAR),
                 pStop->pstrProcessName);

        pReply->ulCount++;
        pEntry = pEntry->Flink;
        ulLength += sizeof(STOP_INFO);
    }

    ReleaseLock(&gStopLock, oldIrql);

    return STATUS_SUCCESS;
}

VOID
OnClearStop(
    _In_ unsigned char cMajor,
    _In_ unsigned char cMinor,
    _In_ BOOLEAN bPreOperation)
{
    PLIST_ENTRY pEntry = NULL;
    PSTOP_DATA pStop = NULL;
    unsigned char cStopMajor;
    unsigned char cStopMinor;
    KIRQL oldIrql;

    FLT_ASSERT(gStopLock);
    FLT_ASSERT(gpListStopHead);

    oldIrql = ExclusiveLock(&gStopLock);
    pEntry = gpListStopHead->Flink;
    while (pEntry != gpListStopHead)
    {
        pStop = CONTAINING_RECORD(pEntry, STOP_DATA, listEntry);
        cStopMajor = pStop->cMajor;
        cStopMinor = pStop->cMinor;

        if ((pStop->bPreOperation == bPreOperation) && (cStopMajor == cMajor))
        {
            if (cStopMinor != IRP_NONE)
            {
                if (cStopMinor == cMinor)
                {
                    RemoveStopEntry(pStop);
                    RemoveEntryList(pEntry);
                    FreeMemory(pEntry);
                    break;
                }
            }
            else
            {
                RemoveStopEntry(pStop);
                RemoveEntryList(pEntry);
                FreeMemory(pEntry);
                break;
            }
        }
        pEntry = pEntry->Flink;
    }

    ReleaseLock(&gStopLock, oldIrql);
}

VOID
RemoveStopEntry(
    _In_ PSTOP_DATA pStop)
{
    if (pStop != NULL)
    {
        if (pStop->pstrPathContain != NULL)
        {
            FreeMemory(pStop->pstrPathContain);
            pStop->pstrPathContain = NULL;
        }

        if (pStop->pstrProcessName != NULL)
        {
            FreeMemory(pStop->pstrProcessName);
            pStop->pstrProcessName = NULL;
        }
    }
}

NTSTATUS
OnGetStopperNumber(
    _Out_ LONG *plNumber)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLIST_ENTRY pEntry = NULL;
    KIRQL oldIrql;

    FLT_ASSERT(gpListStopHead);
    FLT_ASSERT(gStopLock);

    *plNumber = 0;

    oldIrql = ExclusiveLock(&gStopLock);
    pEntry = gpListStopHead->Flink;
    while (pEntry != gpListStopHead)
    {
        (*plNumber)++;
        pEntry = pEntry->Flink;
    }

    ReleaseLock(&gStopLock, oldIrql);

    return status;
}

NTSTATUS
OnAddStop(
    _In_ unsigned char cMajor,
    _In_ unsigned char cMinor,
    _In_ BOOLEAN bPreOperation,
    _In_ PWCHAR pstrProcessName,
    _In_ PWCHAR pstrPathContain,
    _In_ LONG lPid,
    _In_ LONG lCount,
    _In_ BOOLEAN bCrash)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSTOP_DATA pStop = NULL;
    PLIST_ENTRY pEntry = NULL;
    PSTOP_DATA pExistingStop = NULL;
    BOOLEAN bAddNewEntry = TRUE;
    SIZE_T stSize = 0;
    KIRQL oldIrql;

    if (IsEnabled() == FALSE)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    FLT_ASSERT(gpListStopHead);
    FLT_ASSERT(gStopLock);

    oldIrql = ExclusiveLock(&gStopLock);

    pStop = (PSTOP_DATA) AllocateMemory(POOL_FLAG_NON_PAGED,
                                        sizeof(STOP_DATA),
                                        STOPPER_TAG);
    if (pStop == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    pStop->cMajor = cMajor;
    pStop->cMinor = cMinor;
    pStop->bPreOperation = bPreOperation;
    pStop->lPid = lPid;
    pStop->lCount = lCount;
    pStop->bCrash = bCrash;

    if ((pstrProcessName != NULL) && (wcslen(pstrProcessName) > 0))
    {
        stSize = (wcslen(pstrProcessName) + 1) * sizeof(WCHAR);
        pStop->pstrProcessName = (PWCHAR) AllocateMemory(POOL_FLAG_NON_PAGED,
                                                         stSize,
                                                         STOPPER_TAG);
        if (pStop->pstrProcessName == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        RtlCopyMemory(pStop->pstrProcessName, pstrProcessName, stSize);
    }

    if ((pstrPathContain != NULL) && (wcslen(pstrPathContain) > 0))
    {
        stSize = (wcslen(pstrPathContain) + 1) * sizeof(WCHAR);
        pStop->pstrPathContain = (PWCHAR) AllocateMemory(POOL_FLAG_NON_PAGED,
                                                         stSize,
                                                         STOPPER_TAG);
        if (pStop->pstrPathContain == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        RtlCopyMemory(pStop->pstrPathContain, pstrPathContain, stSize);
    }

    pEntry = gpListStopHead->Flink;
    while (pEntry != gpListStopHead)
    {
        pExistingStop = CONTAINING_RECORD(pEntry, STOP_DATA, listEntry);
        if ((pExistingStop->cMajor == pStop->cMajor) &&
            (pExistingStop->bPreOperation == pStop->bPreOperation) &&
            (pExistingStop->lPid == pStop->lPid) &&
            (((pExistingStop->pstrPathContain != NULL) && (pStop->pstrPathContain != NULL)) ? 
            (_wcsicmp(pExistingStop->pstrPathContain, pStop->pstrPathContain) == 0) : FALSE) &&
            (((pExistingStop->pstrProcessName != NULL) && (pStop->pstrProcessName != NULL)) ?
            (_wcsicmp(pExistingStop->pstrProcessName, pStop->pstrProcessName) == 0) : FALSE))
        {
            bAddNewEntry = FALSE;
            pExistingStop->cMinor = pStop->cMinor;
            pExistingStop->bCrash = pStop->bCrash;
            pExistingStop->lCount = pStop->lCount;

            break;
        }
        pEntry = pEntry->Flink;
    }

    if (bAddNewEntry == TRUE)
    {
        InsertTailList(gpListStopHead, &pStop->listEntry);
    }

Cleanup:
    if (NT_SUCCESS(status) == FALSE)
    {
        RemoveStopEntry(pStop);
    }

    ReleaseLock(&gStopLock, oldIrql);

    return status;
}

NTSTATUS
OnCleanupStop(
    _Out_ LONG *plNumber)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLIST_ENTRY pEntry = NULL;
    PSTOP_DATA pStop = NULL;
    KIRQL oldIrql;

    FLT_ASSERT(gpListStopHead);
    FLT_ASSERT(gStopLock);
    FLT_ASSERT(plNumber);

    *plNumber = 0;

    oldIrql = ExclusiveLock(&gStopLock);

    while (IsListEmpty(gpListStopHead) != TRUE)
    {
        pEntry = RemoveHeadList(gpListStopHead);
        pStop = CONTAINING_RECORD(pEntry, STOP_DATA, listEntry);
        RemoveStopEntry(pStop);
        FreeMemory(pEntry);
        *plNumber++;
    }

    ReleaseLock(&gStopLock, oldIrql);

    return status;
}

NTSTATUS
InitLock(
    _Inout_ PERESOURCE *pLock)
{
    NTSTATUS status = STATUS_SUCCESS;

    *pLock = (PERESOURCE) AllocateMemory(POOL_FLAG_NON_PAGED,
                                         sizeof(ERESOURCE),
                                         STOPPER_TAG);
    status = ExInitializeResourceLite(*pLock);

    if (NT_SUCCESS(status) == FALSE)
    {
        FreeMemory(*pLock);
        *pLock = NULL;
    }

    return status;
}

