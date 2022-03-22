#include "hook.h"


BOOLEAN CVSet_EPT_PAGE_HOOK(PVOID HookFunc,BOOLEAN vmlaunch)
{

    ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
	if (vmlaunch)
	{
		    vmx_vmcall(VMCALL_HOOK_EPT_PAGE, HookFunc);
			DbgPrintLog("[+] HOOK From VM-ROOT\n");
			CvKeInvalidateEpt();
			return TRUE;
		
	}
	else
	{
		if (CVHOOKFromRegularMode(HookFunc, vmlaunch))
		{
			DbgPrintLog("[+] HOOK From Regular Kernel Mode\n");
			return TRUE;
		}
	}
	DbgPrintLog("[!] HOOK Not Apply !\n");
	return FALSE;
}
VOID CvKeInvalidateEpt() 
{
	KeIpiGenericCall(CvInvalidateEptByVmcall, pEptState->EptPointer.all);
}
VOID CvInvalidateEptByVmcall(ULONG64 EptContext) 
{
	if (EptContext == NULL) 
	{
		vmx_vmcall(VMCALL_INVEPT_ALL_CONTEXT);
	}
	else
	{
		vmx_vmcall(VMCALL_INVEPT_SINGLE_CONTEXT, EptContext);
	}
}
BOOLEAN CVHOOKFromRegularMode(PVOID HookFunc, BOOLEAN vmlaunch) 
{
	PVOID VirtualTarget;
	ULONG64 phyaddress;
	ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
	VirtualTarget = PAGE_ALIGN(HookFunc);
	phyaddress = MmGetPhysicalAddress(VirtualTarget).QuadPart;
	if (phyaddress ==NULL)
	{
		DbgPrintLog("[!] Error: Get HookFunc phyaddress Failed\n");
	}
	if (!EptSplit2Mto4K(pEptState->EptPageTable, phyaddress, CpuNumber))
	{
		DbgPrintLog("[!] Error: Split page failed : 0x%llx\n", phyaddress);
		return FALSE;
	}
	PPTE TargetPage = EptGetPTEENTRY(pEptState->EptPageTable, phyaddress);
	if (!TargetPage)
	{
		DbgPrintLog("[!] Error: Failed to get PML1 entry of the target address\n");
		return FALSE;
	}
	TargetPage->Bits.exec_access_supervisor = 0;
	if (vmlaunch)
	{
		InveptSingleContext(pEptState->EptPointer.all);
	}
	return TRUE;
}