#pragma once
#include "common.h"
#include "hook.h"
#include "CVvmexitEntry.h"


typedef enum
{
	VMCALL_VMXOFF = 0,
	VMCALL_HOOK_EPT_PAGE = 1,
	VMCALL_INVEPT_ALL_CONTEXT = 2,
	VMCALL_INVEPT_SINGLE_CONTEXT = 3

}VMCALL_ARG;

typedef struct _INVEPT_DESCRIPTOR
{
	ULONG64 EptPointer;
	ULONG64  Reserveds;
}INVEPT_DESCRIPTOR, * PINVEPT_DESCRIPTOR;

typedef enum _INVEPT_TYPE
{
	SINGLE_CONTEXT = 0x00000001,
	ALL_CONTEXTS = 0x00000002
};

VOID InveptAllContexts();
VOID InveptSingleContext(UINT64 EptPonter);

VOID DealVmcall(ULONG64 VMCALL_ARG, ULONG64 OptionalParam1);