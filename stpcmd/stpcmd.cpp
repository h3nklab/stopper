#include <iostream>
#include <Windows.h>
#include <fltUser.h>

#include "share.h"

typedef struct _IRP_ENTRY
{
    wchar_t strIrpKey[8];
    wchar_t strIrpValue[64];
} IRP_ENTRY, *PIRP_ENTRY;

IRP_ENTRY gMjIrp[] =
{
    {L"   0", L"IRP_MJ_CREATE"},
    {L"   1", L"IRP_MJ_CREATE_NAMED_PIPE"},
    {L"   2", L"IRP_MJ_CLOSE"},
    {L"   3", L"IRP_MJ_READ"},
    {L"   4", L"IRP_MJ_WRITE"},
    {L"   5", L"IRP_MJ_QUERY_INFORMATION"},
    {L"   6", L"IRP_MJ_SET_INFORMATION"},
    {L"   7", L"IRP_MJ_QUERY_EA"},
    {L"   8", L"IRP_MJ_SET_EA"},
    {L"   9", L"IRP_MJ_FLUSH_BUFFERS"},
    {L"  10", L"IRP_MJ_QUERY_VOLUME_INFORMATION"},
    {L"  11", L"IRP_MJ_SET_VOLUME_INFORMATION"},
    {L"  12", L"IRP_MJ_DIRECTORY_CONTROL"},
    {L"  13", L"IRP_MJ_FILE_SYSTEM_CONTROL"},
    {L"  14", L"IRP_MJ_DEVICE_CONTROL"},
    {L"  15", L"IRP_MJ_INTERNAL_DEVICE_CONTROL"},
    {L"  16", L"IRP_MJ_SHUTDOWN"},
    {L"  17", L"IRP_MJ_LOCK_CONTROL"},
    {L"  18", L"IRP_MJ_CLEANUP"},
    {L"  19", L"IRP_MJ_CREATE_MAILSLOT"},
    {L"  20", L"IRP_MJ_QUERY_SECURITY"},
    {L"  21", L"IRP_MJ_SET_SECURITY"},
    {L"  22", L"IRP_MJ_POWER"},
    {L"  23", L"IRP_MJ_SYSTEM_CONTROL"},
    {L"  24", L"IRP_MJ_DEVICE_CHANGE"},
    {L"  25", L"IRP_MJ_QUERY_QUOTA"},
    {L"  26", L"IRP_MJ_SET_QUOTA"},
    {L"  27", L"IRP_MJ_PNP"},
    {L"  28", L"IRP_MJ_PNP_POWER: IRP_MJ_PNP is Obsolete...."},
    {L"  29", L"IRP_MJ_MAXIMUM_FUNCTION"}
};

IRP_ENTRY gPnpMnIrp[] =
{
    {L"  0", L"IRP_MN_START_DEVICE"},
    {L"  1", L"IRP_MN_QUERY_REMOVE_DEVICE"},
    {L"  1", L"IRP_MN_SCSI_CLASS"},
    {L"  2", L"IRP_MN_REMOVE_DEVICE"},
    {L"  3", L"IRP_MN_CANCEL_REMOVE_DEVICE"},
    {L"  4", L"IRP_MN_STOP_DEVICE"},
    {L"  5", L"IRP_MN_QUERY_STOP_DEVICE"},
    {L"  6", L"IRP_MN_CANCEL_STOP_DEVICE"},
    {L"  7", L"IRP_MN_QUERY_DEVICE_RELATIONS"},
    {L"  8", L"IRP_MN_QUERY_INTERFACE"},
    {L"  9", L"IRP_MN_QUERY_CAPABILITIES"},
    {L" 10", L"IRP_MN_QUERY_RESOURCES"},
    {L" 11", L"IRP_MN_QUERY_RESOURCE_REQUIREMENTS"},
    {L" 12", L"IRP_MN_QUERY_DEVICE_TEXT"},
    {L" 13", L"IRP_MN_FILTER_RESOURCE_REQUIREMENTS"},
    {L" 15", L"IRP_MN_READ_CONFIG"},
    {L" 16", L"IRP_MN_WRITE_CONFIG"},
    {L" 17", L"IRP_MN_EJECT"},
    {L" 18", L"IRP_MN_SET_LOCK"},
    {L" 19", L"IRP_MN_QUERY_ID"},
    {L" 20", L"IRP_MN_QUERY_PNP_DEVICE_STATE"},
    {L" 21", L"IRP_MN_QUERY_BUS_INFORMATION"},
    {L" 22", L"IRP_MN_DEVICE_USAGE_NOTIFICATION"},
    {L" 23", L"IRP_MN_SURPRISE_REMOVAL"},
    {L" 25", L"IRP_MN_DEVICE_ENUMERATED"}
};

IRP_ENTRY gPowerMnIrp[] =
{
    {L"  0", L"IRP_MN_WAIT_WAKE"},
    {L"  1", L"IRP_MN_POWER_SEQUENCE"},
    {L"  2", L"IRP_MN_SET_POWER"},
    {L"  3", L"IRP_MN_QUERY_POWER"}
};

IRP_ENTRY gSysCtrlMnIrp[] =
{
    {L"  0", L"IRP_MN_QUERY_ALL_DATA"},
    {L"  1", L"IRP_MN_QUERY_SINGLE_INSTANCE"},
    {L"  2", L"IRP_MN_CHANGE_SINGLE_INSTANCE"},
    {L"  3", L"IRP_MN_CHANGE_SINGLE_ITEM"},
    {L"  4", L"IRP_MN_ENABLE_EVENTS"},
    {L"  5", L"IRP_MN_DISABLE_EVENTS"},
    {L"  6", L"IRP_MN_ENABLE_COLLECTION"},
    {L"  7", L"IRP_MN_DISABLE_COLLECTION"},
    {L"  8", L"IRP_MN_REGINFO"},
    {L"  9", L"IRP_MN_EXECUTE_METHOD"},
    {L" 11", L"IRP_MN_REGINFO_EX"}
};

IRP_ENTRY gDirCtrlMnIrp[] =
{
    {L"  1", L"IRP_MN_QUERY_DIRECTORY"},
    {L"  2", L"IRP_MN_NOTIFY_CHANGE_DIRECTORY"},
    {L"  3", L"IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX"}
};

IRP_ENTRY gFileSysCtrlMnIrp[] =
{
    {L"  0", L"IRP_MN_USER_FS_REQUEST"},
    {L"  1", L"IRP_MN_MOUNT_VOLUME"},
    {L"  2", L"IRP_MN_VERIFY_VOLUME"},
    {L"  3", L"IRP_MN_LOAD_FILE_SYSTEM"},
    {L"  4", L"IRP_MN_TRACK_LINK...To be obsoleted soon"},
    {L"  4", L"IRP_MN_KERNEL_CALL"}
};

IRP_ENTRY gLockCtrlMnIrp[] =
{
    {L"  1", L"IRP_MN_LOCK"},
    {L"  2", L"IRP_MN_UNLOCK_SINGLE"},
    {L"  3", L"IRP_MN_UNLOCK_ALL"},
    {L"  4", L"IRP_MN_UNLOCK_ALL_BY_KEY"}
};

IRP_ENTRY gFlushMnIrp[] =
{
    {L"  1", L"IRP_MN_FLUSH_AND_PURGE"},
    {L"  2", L"IRP_MN_FLUSH_DATA_ONLY"},
    {L"  3", L"IRP_MN_FLUSH_NO_SYNC"},
    {L"  4", L"IRP_MN_FLUSH_DATA_SYNC_ONLY"},
};

IRP_ENTRY gLanMgrMnIrp[] =
{
    {L"   0", L"IRP_MN_NORMAL"},
    {L"   1", L"IRP_MN_DPC"},
    {L"   2", L"IRP_MN_MDL"},
    {L"   4", L"IRP_MN_COMPLETE"},
    {L"   8", L"IRP_MN_COMPRESSED"},
    {L"   3", L"IRP_MN_MDL_DPC"},
    {L"   6", L"IRP_MN_COMPLETE_MDL"},
    {L"   7", L"IRP_MN_COMPLETE_MDL_DPC"},
    {L"  24", L"IRP_MN_QUERY_LEGACY_BUS_INFORMATION"},
    {L" 512", L"IO_CHECK_CREATE_PARAMETERS"},
    {L"1024", L"IO_ATTACH_DEVICE"}
};

void
ShowIrpList(
    _In_ PIRP_ENTRY pList,
    _In_ ULONG ulNumItem,
    _In_ PCWSTR pstrHeader)
{
    std::wcout << pstrHeader << std::endl;

    for (size_t st = 0; st < ulNumItem; st++)
    {
        std::wcout << pList[st].strIrpKey << L"  " << pList[st].strIrpValue << std::endl;
    }

    std::wcout << L"**************************************\n";
}

void
Usage(
    _In_ PCWSTR pstrExe)
{
    std::wcout << L"stpcmd version 0.1.0.0\n";
    std::wcout << pstrExe << L" <command>\n";
    std::wcout << L"Copyright(C) 2024 Henky Purnawan\n\n";
    std::wcout << L"Command:\n";
    std::wcout << L"SHOW: Show IRP Major and minor list. See SHOW option\n";
    std::wcout << L"ADD: Add a breakpoint at designated IRP event. See ADD option\n";
    std::wcout << L"DEL: Delete a breakpoint at designated IRP event. See DEL option\n";
    std::wcout << L"CLEAN: Remove all breakpoints\n";
    std::wcout << L"COUNT: Count the breakpoints\n";
    std::wcout << L"CRASH: Crash the machine\n\n";
    std::wcout << L"SHOW option:\n";
    std::wcout << L"   /mj: Show major IRP list\n";
    std::wcout << L"   /mn: Show minor IRP list\n\n";
    std::wcout << L"ADD option:\n";
    std::wcout << L"   /mj <IRP Major number>\n";
    std::wcout << L"   /mn <IRP Minor number>\n";
    std::wcout << L"   /pre <TRUE/FALSE>\n";
    std::wcout << L"   /pid <process ID>\n";
    std::wcout << L"   /proc <process image file name>\n";
    std::wcout << L"   /path <containing path string to break>\n";
    std::wcout << L"   /count <number of hit counts>\n";
    std::wcout << L"   /act <TRUE: crash, FALSE: break>\n\n";
    std::wcout << L"DEL option:\n";
    std::wcout << L"   /mj <IRP Major number>\n";
    std::wcout << L"   /mn <IRP Minor number>\n";
}

void
OnShow(
    _In_ int argc,
    _In_ wchar_t **argv)
{
    for (int i = 0; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"/mj") == 0)
        {
            ShowIrpList(&gMjIrp[0],
                        sizeof(gMjIrp) / sizeof(IRP_ENTRY),
                        L"**** IRP Major number list ****");
        }
        else if (_wcsicmp(argv[i], L"/mn") == 0)
        {
            ShowIrpList(&gPnpMnIrp[0],
                        sizeof(gPnpMnIrp) / sizeof(IRP_ENTRY),
                        L"**** PNP minor function list ****");
            ShowIrpList(&gPowerMnIrp[0],
                        sizeof(gPowerMnIrp) / sizeof(IRP_ENTRY),
                        L"**** Power minor function list ****");
        }
    }
}

void
OnAdd(
    _In_ int argc,
    _In_ wchar_t **argv)
{
    HRESULT result = S_OK;
    HANDLE hPort = NULL;
    STOP_MESSAGE msg;
    unsigned char cMajor = IRP_NONE;
    unsigned char cMinor = IRP_NONE;
    REPLY_MESSAGE replyMessage = {0};
    DWORD dwBytesReturned = 0;

    ZeroMemory(&msg, sizeof(msg));

    result = FilterConnectCommunicationPort(CONNECTION_PORT_NAME,
                                            FLT_PORT_FLAG_SYNC_HANDLE,
                                            NULL,
                                            0,
                                            NULL,
                                            &hPort);
    if (result != S_OK)
    {
        std::wcout << L"Failed to connect to driver through \""
            << CONNECTION_PORT_NAME << L"\": " << result << std::endl;
        return;
    }

    ZeroMemory(&msg, sizeof(msg));
    ZeroMemory(&replyMessage, sizeof(replyMessage));

    msg.command = CMD_NEW_STOPPER;

    for (int i = 0; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"/mj") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc) || (cMajor != IRP_NONE))
            {
                std::wcout << L"Syntax error on major IRP \"/mj\" option\n";
            }
            else
            {
                cMajor = _wtoi(argv[i]);
            }
        }
        else if (_wcsicmp(argv[i], L"/mn") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc) || (cMinor != IRP_NONE))
            {
                std::wcout << L"Syntax error on major IRP \"/mn\" option\n";
            }
            else
            {
                cMinor = _wtoi(argv[i]);
            }
        }
        else if (_wcsicmp(argv[i], L"/pre") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc))
            {
                std::wcout << L"Syntax error on \"/pre\" option\n";
            }
            else
            {
                if (_wcsicmp(argv[i], L"true") == 0)
                {
                    msg.cPreOperation = 1;
                }
                else
                {
                    msg.cPreOperation = 0;
                }
            }
        }
        else if (_wcsicmp(argv[i], L"/act") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc))
            {
                std::wcout << L"Syntax error on \"/act\" option\n";
            }
            else
            {
                if (_wcsicmp(argv[i], L"true") == 0)
                {
                    msg.cCrash = 1;
                }
                else
                {
                    msg.cCrash = 0;
                }
            }
        }
        else if (_wcsicmp(argv[i], L"/count") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc))
            {
                std::wcout << L"Syntax error on \"/count\" option\n";
            }
            else
            {
                msg.lCount = _wtol(argv[i]);
            }
        }
        else if (_wcsicmp(argv[i], L"/pid") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc))
            {
                std::wcout << L"Syntax error on \"/pid\" option\n";
            }
            else
            {
                msg.lPid = _wtol(argv[i]);
            }
        }
        else if (_wcsicmp(argv[i], L"/proc") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc))
            {
                std::wcout << L"Syntax error on \"/proc\" option\n";
            }
            else
            {
                wcsncpy_s(msg.strProcessName,
                          sizeof(msg.strProcessName) / sizeof(wchar_t),
                          argv[i],
                          wcslen(argv[i]));
            }
        }
        else if (_wcsicmp(argv[i], L"/path") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc))
            {
                std::wcout << L"Syntax error on \"/path\" option\n";
            }
            else
            {
                wcsncpy_s(msg.strPathContain,
                          sizeof(msg.strPathContain) / sizeof(wchar_t),
                          argv[i],
                          wcslen(argv[i]));
            }
        }
        else
        {
            std::wcout << L"Invalid option: " << argv[i] << std::endl;
            return;
        }
    }

    msg.cMajor = cMajor;
    msg.cMinor = cMinor;

    result = FilterSendMessage(hPort,
                               (LPVOID) &msg,
                               sizeof(msg),
                               (LPVOID) &replyMessage,
                               sizeof(REPLY_MESSAGE),
                               &dwBytesReturned);
    if (result != S_OK)
    {
        std::wcout << L"Failed to send data to driver: " << result << std::endl;
    }
    else
    {
        std::wcout << L"Sent to driver: " << replyMessage.status << std::endl;
    }

    CloseHandle(hPort);
}

void
OnDel(
    _In_ int argc,
    _In_ wchar_t **argv)
{
    HRESULT result = S_OK;
    HANDLE hPort = NULL;
    STOP_MESSAGE msg;
    unsigned char cMajor = IRP_NONE;
    unsigned char cMinor = IRP_NONE;
    REPLY_MESSAGE replyMessage = {0};
    DWORD dwBytesReturned = 0;

    ZeroMemory(&msg, sizeof(msg));

    result = FilterConnectCommunicationPort(CONNECTION_PORT_NAME,
                                            FLT_PORT_FLAG_SYNC_HANDLE,
                                            NULL,
                                            0,
                                            NULL,
                                            &hPort);
    if (result != S_OK)
    {
        std::wcout << L"Failed to connect to driver through \""
            << CONNECTION_PORT_NAME << L"\": " << result << std::endl;
        return;
    }

    msg.command = CMD_DEL_STOPPER;

    for (int i = 0; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"/mj") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc) || (cMajor != IRP_NONE))
            {
                std::wcout << L"Syntax error on major IRP \"/mj\" option\n";
            }
            else
            {
                cMajor = _wtoi(argv[i]);
            }
        }
        else if (_wcsicmp(argv[i], L"/mn") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc) || (cMinor != IRP_NONE))
            {
                std::wcout << L"Syntax error on minor IRP \"/mn\" option\n";
            }
            else
            {
                cMinor = _wtoi(argv[i]);
            }
        }
        else if (_wcsicmp(argv[i], L"/pre") == 0)
        {
            i++;
            if ((argv[i][0] == L'/') || (i == argc))
            {
                std::wcout << L"Syntax error on operation flag \"/pre\" option\n";
            }
            else
            {
                if (_wcsicmp(argv[i], L"true") == 0)
                {
                    msg.cPreOperation = 1;
                }
                else
                {
                    msg.cPreOperation = 0;
                }
            }
        }
    }

    msg.cMajor = cMajor;
    msg.cMinor = cMinor;

    result = FilterSendMessage(hPort,
                               (LPVOID) &msg,
                               sizeof(msg),
                               (LPVOID) &replyMessage,
                               sizeof(REPLY_MESSAGE),
                               &dwBytesReturned);
    if (result != S_OK)
    {
        std::wcout << L"Failed to send data to driver: " << result << std::endl;
    }
    else
    {
        std::wcout << L"Sent to driver: " << replyMessage.status << std::endl;
    }

    CloseHandle(hPort);
}

void
OnClean()
{
    HRESULT result = S_OK;
    HANDLE hPort = NULL;
    STOP_MESSAGE msg;
    unsigned char cMajor = 0;
    unsigned char cMinor = 0;
    REPLY_MESSAGE replyMessage = {0};
    DWORD dwBytesReturned = 0;

    ZeroMemory(&msg, sizeof(msg));

    result = FilterConnectCommunicationPort(CONNECTION_PORT_NAME,
                                            FLT_PORT_FLAG_SYNC_HANDLE,
                                            NULL,
                                            0,
                                            NULL,
                                            &hPort);
    if (result != S_OK)
    {
        std::wcout << L"Failed to connect to driver through \""
            << CONNECTION_PORT_NAME << L"\": " << result << std::endl;
        return;
    }

    msg.command = CMD_CLEAN_STOPPER;

    msg.cMajor = cMajor;
    msg.cMinor = cMinor;

    result = FilterSendMessage(hPort,
                               (LPVOID) &msg,
                               sizeof(msg),
                               (LPVOID) &replyMessage,
                               sizeof(REPLY_MESSAGE),
                               &dwBytesReturned);
    if (result != S_OK)
    {
        std::wcout << L"Failed to send data to driver: " << result << std::endl;
    }
    else
    {
        std::wcout << L"Sent to driver: " << replyMessage.status << std::endl;
    }

    CloseHandle(hPort);
}

void
OnCrash()
{
    HRESULT result = S_OK;
    HANDLE hPort = NULL;
    STOP_MESSAGE msg;
    unsigned char cMajor = 0;
    unsigned char cMinor = 0;
    REPLY_MESSAGE replyMessage = {0};
    DWORD dwBytesReturned = 0;

    ZeroMemory(&msg, sizeof(msg));

    result = FilterConnectCommunicationPort(CONNECTION_PORT_NAME,
                                            FLT_PORT_FLAG_SYNC_HANDLE,
                                            NULL,
                                            0,
                                            NULL,
                                            &hPort);
    if (result != S_OK)
    {
        std::wcout << L"Failed to connect to driver through \""
            << CONNECTION_PORT_NAME << L"\": " << result << std::endl;
        return;
    }

    msg.command = CMD_CRASH;

    msg.cMajor = cMajor;
    msg.cMinor = cMinor;

    result = FilterSendMessage(hPort,
                               (LPVOID) &msg,
                               sizeof(msg),
                               (LPVOID) &replyMessage,
                               sizeof(REPLY_MESSAGE),
                               &dwBytesReturned);
    if (result != S_OK)
    {
        std::wcout << L"Failed to send data to driver: " << result << std::endl;
    }
    else
    {
        std::wcout << L"Sent to driver: " << replyMessage.status << std::endl;
    }

    CloseHandle(hPort);
}

void
OnGetStopNumber()
{
    HRESULT result = S_OK;
    HANDLE hPort = NULL;
    STOP_MESSAGE msg;
    unsigned char cMajor = 0;
    unsigned char cMinor = 0;
    REPLY_MESSAGE replyMessage = {0};
    DWORD dwBytesReturned = 0;

    ZeroMemory(&msg, sizeof(msg));

    result = FilterConnectCommunicationPort(CONNECTION_PORT_NAME,
                                            FLT_PORT_FLAG_SYNC_HANDLE,
                                            NULL,
                                            0,
                                            NULL,
                                            &hPort);
    if (result != S_OK)
    {
        std::wcout << L"Failed to connect to driver through \""
            << CONNECTION_PORT_NAME << L"\": " << result << std::endl;
        return;
    }

    msg.command = CMD_GET_STOPPER_NUMBER;

    msg.cMajor = cMajor;
    msg.cMinor = cMinor;

    result = FilterSendMessage(hPort,
                               (LPVOID) &msg,
                               sizeof(msg),
                               (LPVOID) &replyMessage,
                               sizeof(REPLY_MESSAGE),
                               &dwBytesReturned);
    if (result != S_OK)
    {
        std::wcout << L"Failed to send data to driver: " << result << std::endl;
    }
    else
    {
        std::wcout << L"Breakpoint number(s): " << replyMessage.lNumber << std::endl;
    }

    CloseHandle(hPort);
}

int wmain(int argc, wchar_t **argv)
{
    if ((argc < 2) ||
        ((_wcsicmp(argv[1], L"show") != 0) &&
         (_wcsicmp(argv[1], L"add") != 0) &&
         (_wcsicmp(argv[1], L"del") != 0) &&
         (_wcsicmp(argv[1], L"clean") != 0) &&
         (_wcsicmp(argv[1], L"crash") != 0) &&
         (_wcsicmp(argv[1], L"count") != 0)))
    {
        Usage(argv[0]);
    }

    if (_wcsicmp(argv[1], L"show") == 0)
    {
        OnShow(argc - 2, &argv[2]);
    }
    else if (_wcsicmp(argv[1], L"add") == 0)
    {
        OnAdd(argc - 2, &argv[2]);
    }
    else if (_wcsicmp(argv[1], L"del") == 0)
    {
        OnDel(argc - 2, &argv[2]);
    }
    else if (_wcsicmp(argv[1], L"clean") == 0)
    {
        OnClean();
    }
    else if (_wcsicmp(argv[1], L"crash") == 0)
    {
        OnCrash();
    }
    else if (_wcsicmp(argv[1], L"count") == 0)
    {
        OnGetStopNumber();
    }

    return 0;
}
