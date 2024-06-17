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
    _In_ PCWSTR pstrMsg)
{
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

    if (pstrMsg != NULL)
    {
        std::wcout << pstrMsg << std::endl;
    }

    std::wcout << dwError << L": " << pstrErrorMsg << std::endl;
    LocalFree(pstrErrorMsg);
}

DWORD
GetDirectoryChanges(
    _In_ PCWSTR pstrDir)
{
    HANDLE hDir = NULL;
    DWORD dwRet = ERROR_SUCCESS;
    PCHAR pBuffer = NULL;
    PCHAR pNextInfo = NULL;
    DWORD dwBufferLength = 1024 * 10;
    DWORD dwReturnedLength = 0;
    PFILE_NOTIFY_INFORMATION pInfo = NULL;
    PFILE_NOTIFY_INFORMATION pInfoNext = NULL;

    std::wcout << std::endl;
    hDir = CreateFile(
        pstrDir,
        GENERIC_READ | FILE_LIST_DIRECTORY,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);

    if (hDir == INVALID_HANDLE_VALUE)
    {
        dwRet = GetLastError();
        ShowError(__FUNCTIONW__, dwRet, L"Failed opening file");
        return dwRet;
    }

    std::wcout << L"Opened " << pstrDir << L" successfully\n";

    pBuffer = (PCHAR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferLength);

    if (ReadDirectoryChangesW(hDir,
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
                              NULL) == FALSE)
    {
        dwRet = GetLastError();
        ShowError(__FUNCTIONW__, dwRet, NULL);
        goto Cleanup;
    }

    if (dwReturnedLength > sizeof(FILE_NOTIFY_INFORMATION))
    {
        pNextInfo = pBuffer;

        do
        {
            pInfo = (PFILE_NOTIFY_INFORMATION) pNextInfo;
            PWSTR pstrFileName = (PWSTR) HeapAlloc(GetProcessHeap(),
                                                   HEAP_ZERO_MEMORY,
                                                   pInfo->FileNameLength + sizeof(wchar_t));

            CopyMemory(pstrFileName, pInfo->FileName, pInfo->FileNameLength);
            std::wcout << pstrFileName << std::endl;
            HeapFree(GetProcessHeap(), 0, pstrFileName);

            pNextInfo = ((PCHAR) pInfo) + pInfo->NextEntryOffset;
        } while (pInfo->NextEntryOffset != 0);
    }

Cleanup:
    if (pBuffer != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pBuffer);
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

    return (int) GetDirectoryChanges(argv[1]);
}
