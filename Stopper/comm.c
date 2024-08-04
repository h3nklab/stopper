#include <fltKernel.h>
#include <dontuse.h>

#include "share.h"
#include "stopper.h"
#include "mem.h"
#include "features.h"
#include "comm.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StopperConnect)
#pragma alloc_text(PAGE, StopperDisconnect)
#pragma alloc_text(PAGE, StopperMessage)
#endif // ALLOC_PRAGMA

LONG glConnectionCount = 0;

NTSTATUS
StopperConnect(
    _In_ PFLT_PORT pClientPort,
    _In_ PVOID pServerPortCookie,
    _In_ PVOID pConnectionCtx,
    _In_ ULONG ulSizeOfContext,
    _Out_ PVOID *pConnectionPortCookie)
{
    PCOMM_CONTEXT pContext = NULL;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(pServerPortCookie);
    UNREFERENCED_PARAMETER(pConnectionCtx);
    UNREFERENCED_PARAMETER(ulSizeOfContext);

    if (glConnectionCount >= STOPPER_MAX_CONNECTION)
    {
        return STATUS_INVALID_CONNECTION;
    }

    pContext = (PCOMM_CONTEXT) AllocateMemory(POOL_FLAG_NON_PAGED,
                                              sizeof(COMM_CONTEXT),
                                              STOPPER_TAG);
    if (pContext == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pContext->pClientPort = pClientPort;
    *pConnectionPortCookie = pContext;

    InterlockedIncrement(&glConnectionCount);

    return STATUS_SUCCESS;
}

VOID
StopperDisconnect(
    _In_ PVOID pConnectionCookie)
{
    PCOMM_CONTEXT pContext = (PCOMM_CONTEXT) pConnectionCookie;

    PAGED_CODE();

    InterlockedDecrement(&glConnectionCount);
    if (pContext != NULL)
    {
        FltCloseClientPort(ghFilter, &pContext->pClientPort);
        FreeMemory(pContext);
    }
}

NTSTATUS
StopperMessage(
    _In_ PVOID pPortCookie,
    _In_ PVOID pInputBuffer,
    _In_ ULONG ulInputBufferLength,
    _Out_ PVOID pOutputBuffer,
    _In_ ULONG ulOutputBufferLength,
    _Out_ PULONG pulReturnOutputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    CMD_STOPPER pCmd;
    PSTOP_MESSAGE pMsg = NULL;
    PREPLY_MESSAGE pReply = NULL;
    LONG lNumber = 0;

    UNREFERENCED_PARAMETER(pulReturnOutputBufferLength);
    UNREFERENCED_PARAMETER(ulOutputBufferLength);
    UNREFERENCED_PARAMETER(ulInputBufferLength);
    UNREFERENCED_PARAMETER(pPortCookie);

    pReply = (PREPLY_MESSAGE) pOutputBuffer;

    if (pInputBuffer != NULL)
    {
        __try
        {
            pCmd = ((PCOMMAND_MESSAGE) pInputBuffer)->command;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            return status;
        }

        switch (pCmd)
        {
            case CMD_NEW_STOPPER:
                pMsg = (PSTOP_MESSAGE) pInputBuffer;
                status = OnAddStop(pMsg->data.cMajor,
                                   pMsg->data.cMinor,
                                   (pMsg->data.cPreOperation == 0) ? FALSE : TRUE,
                                   pMsg->data.strProcessName,
                                   pMsg->data.strPathContain,
                                   pMsg->data.lPid,
                                   (pMsg->data.lCount == 0) ? 1 : pMsg->data.lCount,
                                   (pMsg->data.cCrash == 0) ? FALSE : TRUE);
                break;

            case CMD_DEL_STOPPER:
                pMsg = (PSTOP_MESSAGE) pInputBuffer;
                OnClearStop(pMsg->data.cMajor,
                            pMsg->data.cMinor,
                            (pMsg->data.cPreOperation == 0) ? FALSE : TRUE);
                break;

            case CMD_CLEAN_STOPPER:
                status = OnCleanupStop(&lNumber);
                pReply->lNumber = lNumber;
                break;

            case CMD_CRASH:
                KeBugCheck(MANUALLY_INITIATED_CRASH1);
                break;

            case CMD_GET_STOPPER_NUMBER:
                status = OnGetStopperNumber(&lNumber);
                pReply->lNumber = lNumber;
                break;

            case CMD_GET_STOPPER_INFO:
                status = OnGetStopperInfo(pOutputBuffer, ulOutputBufferLength);
                break;

            default:
                status = STATUS_INVALID_PARAMETER;
                break;
        }
    }

    pReply->status = status;

    return status;
}