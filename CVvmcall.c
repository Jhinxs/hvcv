#include "CVvmcall.h"


VOID DealVmcall(ULONG64 VMCALL_ARG, ULONG64 OptionalParam1)
{

	switch (VMCALL_ARG)
	{
	case VMCALL_VMXOFF:
		CVVmxOff();
		break;

	case VMCALL_HOOK_EPT_PAGE:
		CVHOOKFromRegularMode(OptionalParam1, TRUE);
		break;

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
	return vmx_invept(SINGLE_CONTEXT, &Descriptor);
}

VOID InveptAllContexts()
{
	return vmx_invept(ALL_CONTEXTS, NULL);
}