#pragma once

#define STOPPER_MAX_CONNECTION  1

typedef struct _COMM_CONTEXT
{
    PFLT_PORT pClientPort;
} COMM_CONTEXT, *PCOMM_CONTEXT;

NTSTATUS
StopperConnect(
    _In_ PFLT_PORT pClientPort,
    _In_ PVOID pServerPortCookie,
    _In_ PVOID pConnectionCtx,
    _In_ ULONG ulSizeOfContext,
    _Out_ PVOID *pConnectionPortCookie);

VOID
StopperDisconnect(
    _In_ PVOID pConnectionCookie);

NTSTATUS
StopperMessage(
    _In_ PVOID pPortCookie,
    _In_ PVOID pInputBuffer,
    _In_ ULONG ulInputBufferLength,
    _Out_ PVOID pOutputBuffer,
    _In_ ULONG ulOutputBufferLength,
    _Out_ PULONG pulReturnOutputBufferLength);