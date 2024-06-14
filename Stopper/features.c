#include <fltKernel.h>
#include <dontuse.h>

#include "share.h"
#include "stopper.h"
#include "mem.h"
#include "features.h"

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

    while (*pwPtr != L'\\')
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

    FLT_ASSERT(pstrImageFile);
    FLT_ASSERT(pstrCommandLine);

    *pstrImageFile = NULL;
    *pstrCommandLine = NULL;

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

        status = fpZwQueryInformationProcess(ZwCurrentProcess(),
                                             ProcessImageFileName,
                                             pBuffer,
                                             ulLength,
                                             &ulReturnedLength);
    } while ((status == STATUS_INFO_LENGTH_MISMATCH) || (ulLength < ulReturnedLength));

    if (ulReturnedLength - (ULONG) sizeof(UNICODE_STRING) == 0)
    {
        return status;
    }

    pusFullPath = (PUNICODE_STRING) pBuffer;

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
    _In_ unsigned char cMajor,
    _In_ unsigned char cMinor,
    _In_ BOOLEAN bPreOperation)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLIST_ENTRY pEntry = NULL;
    PSTOP_DATA pStop = NULL;
    BOOLEAN bReturn = FALSE;
    PWCHAR pstrProcessName = NULL;
    PWCHAR pstrPath = NULL;
    unsigned char cStopMajor = 0;
    unsigned char cStopMinor = 0;
    BOOLEAN bCrash = FALSE;

    if (IsEnabled() == FALSE)
    {
        return FALSE;
    }

    FLT_ASSERT(gpStopLock);
    FLT_ASSERT(gpListStopHead);

    if (SharedLock(gpStopLock, TRUE) == FALSE)
    {
        return FALSE;
    }

    pEntry = gpListStopHead->Flink;
    while ((pEntry != gpListStopHead) && (bReturn == FALSE))
    {
        pStop = CONTAINING_RECORD(pEntry, STOP_DATA, listEntry);

        cStopMajor = pStop->cMajor;
        cStopMinor = pStop->cMinor;

        if ((cStopMajor == cMajor) && (pStop->bPreOperation == bPreOperation))
        {
            bReturn = TRUE;
            bCrash = pStop->bCrash;

            if (cStopMinor != IRP_NONE)
            {
                if (cStopMinor != cMinor)
                {
                    bReturn = FALSE;
                }
            }
            if ((pStop->pstrProcessName != NULL) || (pStop->pstrPathContain != NULL))
            {

                status = GetProcessImageFile(&pstrProcessName,
                                             &pstrPath);
                if ((NT_SUCCESS(status) == FALSE) ||
                    (pstrProcessName == NULL) ||
                    (pstrPath == NULL))
                {
                    PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                                 ("Failed to get process image name, status = %08X\n",
                                  status));
                    bReturn = FALSE;
                    goto Cleanup;
                }

                if (pstrProcessName != NULL)
                {
                    if (_wcsicmp(pstrProcessName, pStop->pstrProcessName) != 0)
                    {
                        bReturn = FALSE;
                    }
                }

                if (pStop->pstrPathContain != NULL)
                {
                    if (pstrPath != NULL)
                    {
                        if (wcsstr(pstrPath, pStop->pstrPathContain) == NULL)
                        {
                            bReturn = FALSE;
                        }
                    }
                }
            }

            if (pStop->hPid != 0)
            {
                if (pStop->hPid != PsGetCurrentProcessId())
                {
                    bReturn = FALSE;
                }
            }
        }

        pEntry = pEntry->Flink;
    }

Cleanup:
    FreeMemory(pstrProcessName);
    FreeMemory(pstrPath);

    ReleaseLock(gpStopLock);

    if (bReturn == TRUE && bCrash == TRUE)
    {
        KeBugCheck(MANUALLY_INITIATED_CRASH1);
    }
    return bReturn;
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

    FLT_ASSERT(gpStopLock);
    FLT_ASSERT(gpListStopHead);

    if (ExclusiveLock(gpStopLock, TRUE) == TRUE)
    {
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
        ReleaseLock(gpStopLock);
    }
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

    FLT_ASSERT(gpListStopHead);
    FLT_ASSERT(gpStopLock);

    *plNumber = 0;

    if (ExclusiveLock(gpStopLock, TRUE) == TRUE)
    {
        pEntry = gpListStopHead->Flink;
        while (pEntry != gpListStopHead)
        {
            (*plNumber)++;
            pEntry = pEntry->Flink;
        }
        ReleaseLock(gpStopLock);
    }
    else
    {
        status = STATUS_LOCK_NOT_GRANTED;
    }

    return status;
}

NTSTATUS
OnAddStop(
    _In_ unsigned char cMajor,
    _In_ unsigned char cMinor,
    _In_ BOOLEAN bPreOperation,
    _In_ PWCHAR pstrProcessName,
    _In_ PWCHAR pstrPathContain,
    _In_ HANDLE hPid,
    _In_ BOOLEAN bCrash)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSTOP_DATA pStop = NULL;
    SIZE_T stSize = 0;

    if (IsEnabled() == FALSE)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    FLT_ASSERT(gpListStopHead);
    FLT_ASSERT(gpStopLock);

    if (ExclusiveLock(gpStopLock, TRUE) == TRUE)
    {
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
        pStop->hPid = hPid;
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

        InsertTailList(gpListStopHead, &pStop->listEntry);
        ReleaseLock(gpStopLock);
    }
    else
    {
        status = STATUS_LOGON_NOT_GRANTED;
    }

Cleanup:
    if (NT_SUCCESS(status) == FALSE)
    {
        RemoveStopEntry(pStop);
    }

    return status;
}

NTSTATUS
OnCleanupStop(
    _Out_ LONG *plNumber)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLIST_ENTRY pEntry = NULL;
    PSTOP_DATA pStop = NULL;

    FLT_ASSERT(gpListStopHead);
    FLT_ASSERT(gpStopLock);
    FLT_ASSERT(plNumber);

    *plNumber = 0;

    if (ExclusiveLock(gpStopLock, TRUE) == TRUE)
    {
        while (IsListEmpty(gpListStopHead) != TRUE)
        {
            pEntry = RemoveHeadList(gpListStopHead);
            pStop = CONTAINING_RECORD(pEntry, STOP_DATA, listEntry);
            RemoveStopEntry(pStop);
            FreeMemory(pEntry);
            *plNumber++;
        }
        ReleaseLock(gpStopLock);
    }
    else
    {
        status = STATUS_LOGON_NOT_GRANTED;
    }

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

NTSTATUS
DeleteLock(
    _Inout_ PERESOURCE *pLock)
{
    NTSTATUS status = STATUS_SUCCESS;

    // Acquire the lock before deleting it
    EnableDriver(FALSE);

    status = ExclusiveLock(*pLock, TRUE);
    if (NT_SUCCESS(status) == FALSE)
    {
        return status;
    }

    ReleaseLock(*pLock);
    status = ExDeleteResourceLite(*pLock);
    if (NT_SUCCESS(status) != FALSE)
    {
        FreeMemory(*pLock);
        *pLock = NULL;
    }

    return status;
}