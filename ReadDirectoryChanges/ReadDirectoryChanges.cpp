#include <iostream>
#include <Windows.h>

void
Usage(
    _In_ PCWSTR pstrExe)
{
    std::wcout << L"ReadDiretoryChanges.exe <Directory full path>\n";
}

void
ShowError(
    _In_ PCWSTR pstrFunction,
    _In_ DWORD dwError,
    _In_ PCWSTR pstrFormat,
    _In_ ...)
{
    va_list pArgs;
    WCHAR strMsg[2048] = {L'\0'};
    int iResult = 0;
    PWSTR pstrErrorMsg = NULL;
    size_t stLength = 0;
    DWORD dwRet = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                                NULL,
                                dwError,
                                0,
                                (LPTSTR)&pstrErrorMsg,
                                0,
                                NULL);
    if (dwRet == 0)
    {
        std::wcout << L"Failed to get error message for " << dwError 
            << L": " << GetLastError() << std::endl;

        return;
    }

    if (pstrFormat != NULL)
    {
        va_start(pArgs, pstrFormat);
        iResult = vswprintf_s(strMsg, sizeof(strMsg) / sizeof(WCHAR), pstrFormat, pArgs);
        va_end(pArgs);
        if (iResult != -1)
        {
            std::wcout << strMsg << std::endl;
        }
    }

    std::wcout << dwError << L": " << pstrErrorMsg << std::endl;
    LocalFree(pstrErrorMsg);
}

wchar_t *
GetActionString(
    _In_ DWORD dwAction)
{
    static wchar_t strAction[32];

    switch (dwAction)
    {
        case FILE_ACTION_ADDED:
            wcscpy_s(strAction, sizeof(strAction) / sizeof(wchar_t), L"Added");
            break;

        case FILE_ACTION_REMOVED:
            wcscpy_s(strAction, sizeof(strAction) / sizeof(wchar_t), L"Removed");
            break;

        case FILE_ACTION_MODIFIED:
            wcscpy_s(strAction, sizeof(strAction) / sizeof(wchar_t), L"Modified");
            break;

        case FILE_ACTION_RENAMED_OLD_NAME:
            wcscpy_s(strAction, sizeof(strAction) / sizeof(wchar_t), L"Renamed (Old name)");
            break;

        case FILE_ACTION_RENAMED_NEW_NAME:
            wcscpy_s(strAction, sizeof(strAction) / sizeof(wchar_t), L"Renamed (New name)");
            break;

        default:
            wcscpy_s(strAction, sizeof(strAction) / sizeof(wchar_t), L"Unknown action");
    }

    return strAction;
}

DWORD
GetDirectoryChanges(
    _In_ PCWSTR pstrDir,
    _In_ PCWSTR pstrOption)
{
    HANDLE hDir = NULL;
    DWORD dwRet = ERROR_SUCCESS;
    PCHAR pBuffer = NULL;
    PCHAR pNextInfo = NULL;
    DWORD dwBufferLength = 1024 * 10;
    DWORD dwReturnedLength = 0;
    PWSTR pstrPath = NULL;
    PFILE_NOTIFY_INFORMATION pInfo = NULL;
    PFILE_NOTIFY_INFORMATION pInfoNext = NULL;
    BOOL bWrite = FALSE;
    DWORD dwAccess = 0;
    BOOL bRet = FALSE;
    DWORD dwCount = 0;

    std::wcout << std::endl;

    if (pstrOption != NULL)
    {
        if (_wcsicmp(pstrOption, L"/w") == 0)
        {
            std::wcout << L"Enabling write mode\n";
            bWrite = TRUE;
        }
    }

    dwAccess = (bWrite ? GENERIC_WRITE : 0) | GENERIC_READ | FILE_LIST_DIRECTORY;
    printf("Access mode: 0x%X\n", dwAccess);

    hDir = CreateFile(
        pstrDir,
        dwAccess,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);

    if (hDir == INVALID_HANDLE_VALUE)
    {
        dwRet = GetLastError();
        ShowError(__FUNCTIONW__, dwRet, L"Failed opening file %ws", pstrDir);
        return dwRet;
    }

    dwReturnedLength = GetFinalPathNameByHandle(hDir,
                                                pstrPath,
                                                dwReturnedLength,
                                                0);
    if (dwReturnedLength == 0)
    {
        dwRet = GetLastError();
        ShowError(__FUNCTIONW__, dwRet, L"Failed getting actual path %ws", pstrDir);
        goto Cleanup;
    }

    pstrPath = (PWSTR) HeapAlloc(GetProcessHeap(),
                                 HEAP_ZERO_MEMORY,
                                 dwReturnedLength * sizeof(WCHAR));

    if (pstrPath == NULL)
    {
        dwRet = GetLastError();
        ShowError(__FUNCTIONW__, dwRet, L"Failed to allocate memory");
        goto Cleanup;
    }

    dwReturnedLength = GetFinalPathNameByHandle(hDir,
                                                pstrPath,
                                                dwReturnedLength,
                                                0);

    std::wcout << L"Opened " << pstrPath << L" successfully\n";

    pBuffer = (PCHAR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferLength);

    while (TRUE)
    {
        bRet = ReadDirectoryChangesW(hDir,
                                     pBuffer,
                                     dwBufferLength,
                                     FALSE,
                                     FILE_NOTIFY_CHANGE_FILE_NAME |
                                     FILE_NOTIFY_CHANGE_DIR_NAME |
                                     FILE_NOTIFY_CHANGE_ATTRIBUTES |
                                     FILE_NOTIFY_CHANGE_SIZE |
                                     FILE_NOTIFY_CHANGE_LAST_WRITE |
                                     FILE_NOTIFY_CHANGE_LAST_ACCESS |
                                     FILE_NOTIFY_CHANGE_CREATION |
                                     FILE_NOTIFY_CHANGE_SECURITY,
                                     &dwReturnedLength,
                                     NULL,
                                     NULL);
        if (bRet == FALSE)
        {
            ShowError(__FUNCTIONW__,
                      GetLastError(),
                      L"Failed on ReadDirectoryChanges");
            break;
        }

        std::wcout << "Received " << dwReturnedLength << L" bytes of notification\n";
        dwCount = 0;

        if (dwReturnedLength == 0)
        {
            // This means that we don't have enough buffer
            HeapFree(GetProcessHeap(), 0, pBuffer);
            dwBufferLength *= 2;
            if (dwBufferLength > (1024 * 64))
            {
                std::wcout << L"Out of memory we can allocate: " << dwBufferLength << std::endl;
                break;
            }

            pBuffer = (PCHAR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferLength);
            if (pBuffer == NULL)
            {
                std::wcout << L"Failed to allocate " << dwBufferLength << L" bytes of memory\n";
                goto Cleanup;
            }

            std::wcout << L"Reallocate memory to " << dwBufferLength << L" bytes\n";
            continue;
        }

        if (dwReturnedLength > sizeof(FILE_NOTIFY_INFORMATION))
        {
            pNextInfo = pBuffer;

            do
            {
                dwCount++;
                pInfo = (PFILE_NOTIFY_INFORMATION) pNextInfo;
                PWSTR pstrFileName = (PWSTR) HeapAlloc(GetProcessHeap(),
                                                       HEAP_ZERO_MEMORY,
                                                       pInfo->FileNameLength + sizeof(wchar_t));

                CopyMemory(pstrFileName, pInfo->FileName, pInfo->FileNameLength);
                std::wcout << L"    " << dwCount << L". " << pstrFileName << L": " << GetActionString(pInfo->Action) << std::endl;
                HeapFree(GetProcessHeap(), 0, pstrFileName);

                pNextInfo = ((PCHAR) pInfo) + pInfo->NextEntryOffset;
            } while (pInfo->NextEntryOffset != 0);
        }
        else
        {
            std::wcout << L"Returned memory: " << dwReturnedLength << L" bytes\n";
            std::wcout << L"Expected returned memory: " << sizeof(FILE_NOTIFY_INFORMATION) << L" bytes\n";
        }

        ZeroMemory(pBuffer, dwBufferLength);
    }

Cleanup:
    if (pBuffer != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }

    if (pstrPath != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pstrPath);
    }

    if (hDir != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDir);
    }
    return dwRet;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2)
    {
        Usage(argv[0]);
        return -1;
    }

    return (int) GetDirectoryChanges(argv[1],
                                     (argc > 2) ? argv[2] : NULL);
}
