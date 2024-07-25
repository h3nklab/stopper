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

void
RenameSimulation(
    _In_ PCWSTR pstrDir)
{
    HANDLE hFind = INVALID_HANDLE_VALUE;
    PWSTR pstrFind = nullptr;
    PWSTR pstrFileName = nullptr;
    PWSTR pstrNewFileName = nullptr;
    WIN32_FIND_DATA wfd = {0};
    size_t stLength = 0;

    std::wcout << L"***** IRP_MJ_SET_INFORMATION *****\n";

    stLength = wcslen(pstrDir);
    pstrFind = (PWSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (stLength + 8) * sizeof(wchar_t));
    if (pstrFind == nullptr)
    {
        ShowError(__FUNCTIONW__,
                  GetLastError(),
                  L"Failed to allocate %lu bytes of memory",
                  (stLength + 8) * sizeof(wchar_t));
        goto Cleanup;
    }

    wsprintf(pstrFind, L"%ws\\*", pstrDir);
    hFind = FindFirstFile(pstrFind, &wfd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        ShowError(__FUNCTIONW__,
                  GetLastError(),
                  L"Failed on find first file");
        goto Cleanup;
    }

    do
    {
        if ((_wcsicmp(wfd.cFileName, L".") != 0) &&
            (_wcsicmp(wfd.cFileName, L"..") != 0))
        {
            if (pstrFileName != nullptr)
            {
                HeapFree(GetProcessHeap(), 0, pstrFileName);
                pstrFileName = nullptr;
            }
            if (pstrNewFileName != nullptr)
            {
                HeapFree(GetProcessHeap(), 0, pstrNewFileName);
                pstrNewFileName = nullptr;
            }

            pstrFileName = (PWSTR) HeapAlloc(GetProcessHeap(),
                                             HEAP_ZERO_MEMORY,
                                             (stLength + wcslen(wfd.cFileName) + 8) * sizeof(wchar_t));
            if (pstrFileName == nullptr)
            {
                ShowError(__FUNCTIONW__,
                          GetLastError(),
                          L"Failed to allocate memory for %ws",
                          wfd.cFileName);
                goto Cleanup;
            }

            wsprintf(pstrFileName, L"%ws\\%ws", pstrDir, wfd.cFileName);

            pstrNewFileName = (PWSTR) HeapAlloc(GetProcessHeap(),
                                             HEAP_ZERO_MEMORY,
                                             (wcslen(pstrFileName) + 8) * sizeof(wchar_t));
            if (pstrNewFileName == nullptr)
            {
                ShowError(__FUNCTIONW__,
                          GetLastError(),
                          L"Failed to allocate memory for target rename of %ws",
                          pstrFileName);
                goto Cleanup;
            }

            wsprintf(pstrNewFileName, L"%ws.new", pstrFileName);

            if (MoveFile(pstrFileName, pstrNewFileName) == FALSE)
            {
                ShowError(__FUNCTIONW__,
                          GetLastError(),
                          L"Failed renaming %ws -> %ws",
                          pstrFileName,
                          pstrNewFileName);
                goto Cleanup;
            }

            if (MoveFile(pstrNewFileName, pstrFileName) == FALSE)
            {
                ShowError(__FUNCTIONW__,
                          GetLastError(),
                          L"Failed renaming %ws -> %ws",
                          pstrNewFileName,
                          pstrFileName);
                goto Cleanup;
            }

            std::wcout << L"Renaming processed: " << pstrFileName << L" <-> " << pstrNewFileName << std::endl;
        }
    } while (FindNextFile(hFind, &wfd));
Cleanup:
    if (pstrFind != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pstrFind);
    }
    if (pstrFileName != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pstrFileName);
    }
    if (pstrNewFileName != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pstrNewFileName);
    }
    if (hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
    }
    std::wcout << std::endl;
}

void
SetAttributeSimulation(
    _In_ PCWSTR pstrDir)
{
    HANDLE hFind = INVALID_HANDLE_VALUE;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PWSTR pstrFind = nullptr;
    PWSTR pstrFileName = nullptr;
    WIN32_FIND_DATA wfd = {0};
    size_t stLength = 0;
    DWORD dwAttr = INVALID_FILE_ATTRIBUTES;

    std::wcout << L"***** IRP_MJ_SET_EA *****\n";

    stLength = wcslen(pstrDir);
    pstrFind = (PWSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (stLength + 8) * sizeof(wchar_t));
    if (pstrFind == nullptr)
    {
        ShowError(__FUNCTIONW__,
                  GetLastError(),
                  L"Failed to allocate %lu bytes of memory",
                  (stLength + 8) * sizeof(wchar_t));
        goto Cleanup;
    }

    wsprintf(pstrFind, L"%ws\\*", pstrDir);
    hFind = FindFirstFile(pstrFind, &wfd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        ShowError(__FUNCTIONW__,
                  GetLastError(),
                  L"Failed on find first file");
        goto Cleanup;
    }

    do
    {
        if ((_wcsicmp(wfd.cFileName, L".") != 0) &&
            (_wcsicmp(wfd.cFileName, L"..") != 0))
        {
            pstrFileName = (PWSTR) HeapAlloc(GetProcessHeap(),
                                          HEAP_ZERO_MEMORY,
                                          (stLength + wcslen(wfd.cFileName) + 8) * sizeof(wchar_t));
            if (pstrFileName == nullptr)
            {
                ShowError(__FUNCTIONW__,
                          GetLastError(),
                          L"Failed to allocate memory for %ws",
                          wfd.cFileName);
                goto Cleanup;
            }

            wsprintf(pstrFileName, L"%ws\\%ws", pstrDir, wfd.cFileName);
            break;
        }
    } while (FindNextFile(hFind, &wfd));

    if (pstrFileName != nullptr)
    {
        std::wcout << L"Attempting to change file " << pstrFileName << L" attribute\n";
        dwAttr = GetFileAttributes(pstrFileName);
        if (dwAttr == INVALID_FILE_ATTRIBUTES)
        {
            ShowError(__FUNCTIONW__,
                      GetLastError(),
                      L"Failed to get file %ws attributes",
                      pstrFileName);
            goto Cleanup;
        }

        if (SetFileAttributes(pstrFileName, dwAttr) == FALSE)
        {
            ShowError(__FUNCTIONW__,
                      GetLastError(),
                      L"Failed to set file %ws attributes",
                      pstrFileName);
            goto Cleanup;
        }
    }

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }
    if (hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
    }
    if (pstrFind != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pstrFind);
    }
    if (pstrFileName != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pstrFileName);
    }
}

int wmain(int argc, wchar_t **argv)
{
    int iRet = 0;

    if (argc < 2)
    {
        Usage(argv[0]);
        return -1;
    }

    RenameSimulation(argv[1]);
    SetAttributeSimulation(argv[1]);

    return iRet;
}
