#pragma once
#include "CVEpt.h"
#include "CVGlobalVaribles.h"
#include "CVvmexitEntry.h"
#include "CVvmcall.h"

#define ADDRMASK_EPT_PML1_OFFSET(_VAR_) (_VAR_ & 0xFFFULL)

BOOLEAN CVSet_EPT_PAGE_HOOK(PVOID TargetFunction, PVOID HookFunction, PVOID* OrigFunction, BOOLEAN vmlaunch);
VOID CVKeInvalidateEpt();
VOID CVInvalidateEptByVmcall(ULONG64 EptContext);
BOOLEAN CVHOOKFromRegularMode(PVOID TargetFunction, PVOID HookFunction, PVOID* OrigFunction, BOOLEAN vmlaunch);
BOOLEAN CVEptHookBuild(PEPT_FAKE_PAGE Hook, PVOID TargetFunction, PVOID HookFunction, PVOID* OrigFunction);


NTSTATUS NtTerminateProcessHook(
	HANDLE            ProcessHandle,
	NTSTATUS           ExitStatus

);
NTSTATUS(*NtTerminateProcessOrig)(
	HANDLE            ProcessHandle,
	NTSTATUS           ExitStatus
	);

UCHAR* PsGetProcessImageFileName(
	__in PEPROCESS Process
);
VOID CVEptMakeHookJumpBytes(PCHAR TargetBuffer, SIZE_T TargetAddress);