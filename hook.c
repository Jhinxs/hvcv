#include "hook.h"
#include "lde64.h"

BOOLEAN CVSet_EPT_PAGE_HOOK(PVOID TargetFunction, PVOID HookFunction, PVOID* OrigFunction,BOOLEAN vmlaunch)
{

    ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
	if (vmlaunch)
	{
		    vmx_vmcall(VMCALL_HOOK_EPT_PAGE, TargetFunction, HookFunction, OrigFunction);
			DbgPrintLog("[+] HOOK From VM-ROOT\n");
			CVKeInvalidateEpt();
			return TRUE;
		
	}
	else
	{
		if (CVHOOKFromRegularMode(TargetFunction, HookFunction, OrigFunction, vmlaunch))
		{
			DbgPrintLog("[+] HOOK From Regular Kernel Mode\n");
			return TRUE;
		}
	}
	DbgPrintLog("[!] HOOK Not Apply !\n");
	return FALSE;
}
VOID CVKeInvalidateEpt() 
{
	KeIpiGenericCall(CVInvalidateEptByVmcall, pEptState->EptPointer.all);
}
VOID CVInvalidateEptByVmcall(ULONG64 EptContext) 
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
BOOLEAN CVHOOKFromRegularMode(PVOID TargetFunction, PVOID HookFunction, PVOID* OrigFunction, BOOLEAN vmlaunch)
{
	KIRQL irql;
	PVOID VirtualTarget;
	ULONG64 phyaddress;
	ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
	VirtualTarget = PAGE_ALIGN(TargetFunction);
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
	/// 

	PEPT_FAKE_PAGE Fake_Page_Entry = MallocFakePageFromPagePoolList();
	if (!Fake_Page_Entry)
	{
		DbgPrintLog("[!] Error: Failed to Allocate Pool For Fake Page\n");
		return FALSE;
	}
	RtlCopyMemory(&Fake_Page_Entry->FakePageCode[0], VirtualTarget, PAGE_SIZE);

	Fake_Page_Entry->PhyAddr = PAGE_ALIGN(phyaddress);
	Fake_Page_Entry->PhyPFN = phyaddress >> 12;
	Fake_Page_Entry->FakeEntryForX.Bits.read_access = 0;
	Fake_Page_Entry->FakeEntryForX.Bits.write_access = 0;
	Fake_Page_Entry->FakeEntryForX.Bits.exec_access_supervisor = 1;
	Fake_Page_Entry->FakeEntryForX.Bits.PhyPagePFN = MmGetPhysicalAddress(&Fake_Page_Entry->FakePageCode).QuadPart >> 12;
	
	KeAcquireSpinLock(&GLock, &irql);
	InsertHeadList(&pEptState->FakePageList, &Fake_Page_Entry->POOL_LIST);
	KeReleaseSpinLock(&GLock, irql);

	Fake_Page_Entry->FakeEntryForRW = *TargetPage;
	Fake_Page_Entry->FakeEntryForRW.Bits.read_access = 1;
	Fake_Page_Entry->FakeEntryForRW.Bits.write_access = 1;
	Fake_Page_Entry->FakeEntryForRW.Bits.exec_access_supervisor = 0;

	if (!CVEptHookBuild(Fake_Page_Entry, TargetFunction, HookFunction, OrigFunction))
	{
		DbgPrintLog("HvEptAddPageHook: Could not build hook.\n");
		return FALSE;
	}

	Fake_Page_Entry->OriginalEntryAddress = TargetPage;
	TargetPage->Bits.read_access = 1;
	TargetPage->Bits.write_access = 1;
	TargetPage->Bits.exec_access_supervisor = 0;
	if (vmlaunch)
	{
		InveptSingleContext(pEptState->EptPointer.all);
	}
	return TRUE;
}
BOOLEAN CVEptHookBuild(PEPT_FAKE_PAGE Hook, PVOID TargetFunction, PVOID HookFunction, PVOID* OrigFunction)
{
	ULONG64 InstructionSkipped = 0;;
	ULONG64 PageOffset;
	PCHAR HookBytes;
	PageOffset = ADDRMASK_EPT_PML1_OFFSET((ULONG64)TargetFunction);
	if ((PageOffset + 12) > PAGE_SIZE - 1)
	{
		DbgPrintLog("[!] Offset spanned a page,Not Solved\n");
		return FALSE;
	}
	for (int i = 0; i < 12; i++)
	{
		InstructionSkipped += LDE((PCHAR)TargetFunction + InstructionSkipped, 64);
	}

	DbgPrintLog("Number of bytes of instruction mem: %d\n", InstructionSkipped);
	HookBytes = (PCHAR)ExAllocatePool(NonPagedPool, InstructionSkipped + 12);

	if (!HookBytes)
	{
		DbgPrintLog("Could not allocate trampoline function buffer.\n");
		return FALSE;
	}

	RtlCopyMemory(HookBytes, TargetFunction, InstructionSkipped);
	CVEptMakeHookJumpBytes(&HookBytes[InstructionSkipped], (ULONG64)TargetFunction + InstructionSkipped);
	*OrigFunction = HookBytes;
	CVEptMakeHookJumpBytes(&Hook->FakePageCode[PageOffset], (ULONG64)HookFunction);
	return TRUE;
}

VOID CVEptMakeHookJumpBytes(PCHAR TargetBuffer, ULONG64 TargetAddress) 
{
	/*
	    12 hook bytes:
	    mov rax,target64
		JMP rax                     
	*/
	TargetBuffer[0] = 0x48;
	TargetBuffer[1] = 0xb8;
	*(ULONG64*)&TargetBuffer[2] = TargetAddress;
	TargetBuffer[10] = 0xFF;
	TargetBuffer[11] = 0xE0;
}

NTSTATUS NtTerminateProcessHook(
	HANDLE            ProcessHandle,
	NTSTATUS           ExitStatus
) 
{
	PEPROCESS pe;
	NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &pe, NULL);
	if (status == STATUS_SUCCESS)
	{
		KIRQL irql = KeGetCurrentIrql();
		char* processname = PsGetProcessImageFileName(pe);
		if (strcmp(processname, "notepad.exe") ==0)
		{
			if (ProcessHandle == (HANDLE)0xffffffffffffffff)
			{
				return NtTerminateProcessOrig(ProcessHandle, ExitStatus);
			}
			return STATUS_ACCESS_DENIED;
		}
		ObDereferenceObject(pe);
	}
	return NtTerminateProcessOrig(ProcessHandle, ExitStatus);
		
}