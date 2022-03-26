#include "CVvmcall.h"

VOID DealVmcall(ULONG64 VMCALL_ARG, ULONG64 OptionalParam1, PVOID HookFunction, PVOID* OrigFunction)
{

	switch (VMCALL_ARG)
	{
	case VMCALL_VMXOFF:
		
		CVVmxOff();
		break;
	case VMCALL_REMOVE_ALLHOOK:

		CVRemoveHookOnStop();
		break;
	case VMCALL_HOOK_EPT_PAGE: 
	{
		ULONG64 targetFunc = OptionalParam1;
		CVSet_EPT_PAGE_HOOK(targetFunc, HookFunction, OrigFunction, TRUE);
		break; 
	}

	case VMCALL_INVEPT_SINGLE_CONTEXT:
		InveptSingleContext(OptionalParam1);
		break;

	case VMCALL_INVEPT_ALL_CONTEXT:
		InveptAllContexts();
		break;

	default:
		DbgPrintLog("[!] Error£ºUknown VMCALL State:%d\n", VMCALL_ARG);
		break;
	}

}

VOID InveptSingleContext(ULONG64 EptPointer)
{
	INVEPT_DESCRIPTOR Descriptor = { EptPointer ,0 };
	return vmx_invept( VEPT_SINGLE_CONTEXT, &Descriptor);
}

VOID InveptAllContexts()
{
	return vmx_invept(VEPT_ALL_CONTEXTS, NULL);
}

VOID InvvpidAllContexts()
{
	return vmx_invvpid(VPID_ALL_CONTEXT, NULL);
}
VOID InvvpidSingleContext(int vpid) 
{
	INVVPID_DESCRIPTOR Descriptor = { vpid ,0 };
	return vmx_invvpid(VPID_SINGLE_CONTEXT, &Descriptor);
}