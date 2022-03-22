#pragma once
#include "CVEpt.h"
#include "CVGlobalVaribles.h"
#include "CVvmexitEntry.h"
#include "CVvmcall.h"

BOOLEAN CVSet_EPT_PAGE_HOOK(PVOID HookFunc, BOOLEAN vmlaunch);
VOID CvKeInvalidateEpt();
VOID CvInvalidateEptByVmcall(ULONG64 EptContext);
BOOLEAN CVHOOKFromRegularMode(PVOID HookFunc, BOOLEAN vmlaunch);