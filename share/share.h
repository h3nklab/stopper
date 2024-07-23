#pragma once

#define IRP_NONE 0xFF

#define MAX_MESSAGE_STRING  512

#define CONNECTION_PORT_NAME    L"\\StopperPort"

typedef enum _CMD_STOPPER
{
    CMD_NEW_STOPPER,
    CMD_DEL_STOPPER,
    CMD_CLEAN_STOPPER,
    CMD_CRASH,
    CMD_GET_STOPPER_NUMBER,
} CMD_STOPPER;

typedef struct _COMMAND_MESSAGE
{
    CMD_STOPPER command;
} COMMAND_MESSAGE, *PCOMMAND_MESSAGE;

typedef struct _STOP_MESSAGE
{
    CMD_STOPPER command;
    unsigned char cMajor;
    unsigned char cMinor;
    unsigned char cPreOperation;
    wchar_t strProcessName[MAX_MESSAGE_STRING];
    wchar_t strPathContain[MAX_MESSAGE_STRING];
    long lPid;
    long lCount;
    unsigned char cCrash;
} STOP_MESSAGE, *PSTOP_MESSAGE;

typedef struct _REPLY_MESSAGE
{
    long status;
    long lNumber;
    wchar_t sString[MAX_MESSAGE_STRING];
} REPLY_MESSAGE, *PREPLY_MESSAGE;