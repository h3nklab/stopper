#include <fltKernel.h>
#include <dontuse.h>

#include "stopper.h"
#include "mem.h"

PVOID
AllocateMemory(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T size,
    _In_ ULONG ulTag)
{
    PVOID p = ExAllocatePool2(flags, size, ulTag);
    if (p == NULL)
    {
        return p;
    }

    RtlZeroMemory(p, size);
    return p;
}

VOID
FreeMemory(
    _In_ PVOID ptr)
{
    if (ptr != NULL)
    {
        ExFreePool(ptr);
    }
}