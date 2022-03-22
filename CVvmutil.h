#pragma once
#include "common.h"

BOOLEAN CVInitialize();
BOOLEAN CVVMShutDown();
BOOLEAN CVCheakVTSupport();
BOOLEAN CVInitEPT();
BOOLEAN VMXvmshutdown();
ULONG64 CVReturnGuestRSP();
ULONG64 CVReturnGuestRIP();

BOOLEAN	CVVMXAllocateMsrBitMap(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
BOOLEAN CVVMXRegionsAllocate(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
BOOLEAN CVVMMAllocateMem(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
VOID DpcInitGuestState(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
VOID DpcShutSetGuestState(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);