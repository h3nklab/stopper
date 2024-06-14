#pragma once

VOID
FreeMemory(
    _In_ PVOID ptr);

PVOID
AllocateMemory(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T size,
    _In_ ULONG ulTag);
