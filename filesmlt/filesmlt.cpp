#include <iostream>
#include <Windows.h>

void Usage(
    _In_ wchar_t *pExe)
{
    std::wcout << L"Usage: " << pExe << " <Full path of folder>\n";
    std::wcout << L"\nThis program simulates on creating/renaming/deleting files in a folder\n";
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
                                (LPTSTR) &pstrErrorMsg,
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

int wmain(int argc, wchar_t **argv)
{
    int iRet = 0;
    HANDLE hDir = INVALID_HANDLE_VALUE;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    PWSTR pFind = nullptr;
    PWSTR pFileName = nullptr;
    PWSTR pNewFileName = nullptr;
    WIN32_FIND_DATA wfd = {0};
    size_t stLength = 0;

    if (argc < 2)
    {
        Usage(argv[0]);
        return -1;
    }

    stLength = wcslen(argv[1]);
    pFind = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (stLength + 8) * sizeof(wchar_t));
    if (pFind == nullptr)
    {
        iRet = (int) GetLastError();

        ShowError(__FUNCTIONW__,
                  (DWORD)iRet,
                  L"Failed to allocate %lu bytes of memory",
                  (stLength + 8) * sizeof(wchar_t));
        goto Cleanup;
    }

    wsprintf(pFind, L"%ws\\*", argv[1]);
    hFind = FindFirstFile(pFind, &wfd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        iRet = (int) GetLastError();
        ShowError(__FUNCTIONW__,
                  (DWORD)iRet,
                  L"Failed on find first file");
        goto Cleanup;
    }

    do
    {
        if ((_wcsicmp(wfd.cFileName, L".") != 0) &&
            (_wcsicmp(wfd.cFileName, L"..") != 0))
        {
            if (pFileName != nullptr)
            {
                HeapFree(GetProcessHeap(), 0, pFileName);
                pFileName = nullptr;
            }
            if (pNewFileName != nullptr)
            {
                HeapFree(GetProcessHeap(), 0, pNewFileName);
                pNewFileName = nullptr;
            }

            pFileName = (PWSTR) HeapAlloc(GetProcessHeap(),
                                          HEAP_ZERO_MEMORY,
                                          (stLength + wcslen(wfd.cFileName) + 8) * sizeof(wchar_t));
            if (pFileName == nullptr)
            {
                iRet = (int) GetLastError();
                ShowError(__FUNCTIONW__,
                          (DWORD) iRet,
                          L"Failed to allocate memory for %ws",
                          wfd.cFileName);
                goto Cleanup;
            }

            wsprintf(pFileName, L"%ws\\%ws", argv[1], wfd.cFileName);

            pNewFileName = (PWSTR) HeapAlloc(GetProcessHeap(),
                                             HEAP_ZERO_MEMORY,
                                             (wcslen(pFileName) + 8) * sizeof(wchar_t));
            if (pNewFileName == nullptr)
            {
                iRet = (int) GetLastError();
                ShowError(__FUNCTIONW__,
                          (DWORD) iRet,
                          L"Failed to allocate memory for target rename of %ws",
                          pFileName);
                goto Cleanup;
            }

            wsprintf(pNewFileName, L"%ws.new", pFileName);

            if (MoveFile(pFileName, pNewFileName) == FALSE)
            {
                iRet = (int) GetLastError();
                ShowError(__FUNCTIONW__,
                          (DWORD) iRet,
                          L"Failed renaming %ws -> %ws",
                          pFileName,
                          pNewFileName);
                goto Cleanup;
            }

            if (MoveFile(pNewFileName, pFileName) == FALSE)
            {
                iRet = (int) GetLastError();
                ShowError(__FUNCTIONW__,
                          (DWORD) iRet,
                          L"Failed renaming %ws -> %ws",
                          pNewFileName,
                          pFileName);
                goto Cleanup;
            }

            std::wcout << L"Renaming processed: " << pFileName << L" <-> " << pNewFileName << std::endl;
        }
    } while (FindNextFile(hFind, &wfd));
Cleanup:
    if (pFind != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pFind);
    }
    if (pFileName != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pFileName);
    }
    if (pNewFileName != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pNewFileName);
    }
    if (hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
    }

    if (hDir != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDir);
    }
    return iRet;
}
