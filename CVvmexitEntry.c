#pragma once
#include "CVGlobalVaribles.h"
#include "CVvmcall.h"
#include "CVEventInject.h"


VOID DealRDMSR(PGUEST_REGS g_GUEST_REGS)
{
	
	LARGE_INTEGER MSR;
	MSR.QuadPart = MAXULONG64;
	switch (g_GUEST_REGS->rcx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		MSR.QuadPart = vmx_vmread(VMCS_GUSTAREA_SYSENTER_CS);
		break;
	}
	case MSR_IA32_SYSENTER_EIP:
	{
		MSR.QuadPart = vmx_vmread(VMCS_GUSTAREA_SYSENTER_EIP);
		break;
	}
	case MSR_IA32_SYSENTER_ESP:
	{
		MSR.QuadPart = vmx_vmread(VMCS_GUSTAREA_SYSENTER_ESP);
		break;
	}
	default:
		MSR.QuadPart = __readmsr(g_GUEST_REGS->rcx);
		break;
	}
	g_GUEST_REGS->rax = MSR.LowPart;
	g_GUEST_REGS->rdx = MSR.HighPart;

}
VOID DealWRMSR(PGUEST_REGS g_GUEST_REGS)
{
	LARGE_INTEGER MSR;
	MSR.QuadPart = MAXULONG64;
	MSR.LowPart = (ULONG32)g_GUEST_REGS->rax;
	MSR.HighPart = (ULONG32)g_GUEST_REGS->rdx;
	switch (g_GUEST_REGS->rcx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		__vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_CS, g_GUEST_REGS->rax);

		break;
	}
	case MSR_IA32_SYSENTER_EIP:
	{
		__vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_ESP, g_GUEST_REGS->rax);

		break;
	}
	case MSR_IA32_SYSENTER_ESP:
	{
		__vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_EIP, g_GUEST_REGS->rax);

		break;
	}
	default:
		
		__writemsr(g_GUEST_REGS->rcx, MSR.QuadPart);
		break;
	}

	

}
VOID DealCrReg(PGUEST_REGS g_GUEST_REGS)
{

	ULONG64 CrQulification;
	CrQulification = vmx_vmread(VMCS_EXIT_QUALIFICTION);
	PACCESS_CR_QUALIFICATION AccessCrQulification = (PACCESS_CR_QUALIFICATION)&CrQulification;
	PULONG64 reg = (PULONG64)&g_GUEST_REGS->rax;
	if (AccessCrQulification->Bits.GPRegister == 4)
	{
		ULONG64 guest_rsp = vmx_vmread(VMCS_GUSTAREA_RSP);
		*reg = guest_rsp;
	}
	switch (AccessCrQulification->Bits.AccessType)
	{
	case 0:                      // mov crx,xxx
		switch (AccessCrQulification->Bits.ControlRegister)
		{
		case 0:
			__vmx_vmwrite(VMCS_GUSTAREA_CR0, reg[AccessCrQulification->Bits.GPRegister]);
			__vmx_vmwrite(CR0_READ_SHADOW, reg[AccessCrQulification->Bits.GPRegister]);
			break;
		case 3:
			
			__vmx_vmwrite(VMCS_GUSTAREA_CR3, reg[AccessCrQulification->Bits.GPRegister]& ~(1ULL << 63));
			InvvpidSingleContext(VPIDTAG);
			break;
		case 4:
			__vmx_vmwrite(VMCS_GUSTAREA_CR4, reg[AccessCrQulification->Bits.GPRegister]);
			__vmx_vmwrite(CR4_READ_SHADOW, reg[AccessCrQulification->Bits.GPRegister]);
			break;
		default:
			DbgPrintLog("Unsupported register %d control registers access when write \n", AccessCrQulification->Bits.ControlRegister);
			break;
		}
		break;
	case 1:                        // mov xxx,crx
		switch (AccessCrQulification->Bits.ControlRegister)
		{
		case 0:
		
			reg[AccessCrQulification->Bits.GPRegister] = vmx_vmread(VMCS_GUSTAREA_CR0);
			break;
		case 3:
			reg[AccessCrQulification->Bits.GPRegister] = vmx_vmread(VMCS_GUSTAREA_CR3);
			break;
		case 4:
			reg[AccessCrQulification->Bits.GPRegister] = vmx_vmread(VMCS_GUSTAREA_CR4);
			break;
		default:
			DbgPrintLog("Unsupported register %d control registers access when read \n", AccessCrQulification->Bits.ControlRegister);

			break;
		}
		break;
	default:
		break;
	}

}
VOID DealCPUID(PGUEST_REGS g_GUEST_REGS)
{
	int uCPUinfo[4] = { 0 };
	__cpuidex(uCPUinfo, (int)g_GUEST_REGS->rax,(int)g_GUEST_REGS->rcx);
	g_GUEST_REGS->rax = uCPUinfo[0];
	g_GUEST_REGS->rbx = uCPUinfo[1];
	g_GUEST_REGS->rcx = uCPUinfo[2];
	g_GUEST_REGS->rdx = uCPUinfo[3];
	
}
VOID CVVmxOff()
{
	
	ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
	ULONG64 cr3 = vmx_vmread(VMCS_GUSTAREA_CR3);
	__writecr3(cr3);
	int INSTRUCTION_LENGH = vmx_vmread(VMCS_INSTRUCTION_LENGH);
	__vmx_vmwrite(VMCS_GUSTAREA_RFLAGS, vmx_vmread(VMCS_GUSTAREA_RFLAGS));
	CVVMX_State[CpuNumber].vmxoff_GuestRip = vmx_vmread(VMCS_GUSTAREA_RIP)+ INSTRUCTION_LENGH;
	CVVMX_State[CpuNumber].vmxoff_GuestRsp = vmx_vmread(VMCS_GUSTAREA_RSP);
	CVVMX_State[CpuNumber].isstopvt = TRUE;
	CVVMX_State[CpuNumber].isstartvt = FALSE;
	CVVMX_State[CpuNumber].NeedIncRip = FALSE;
	__vmx_off();
}
VOID DealRDTSC(PGUEST_REGS g_GUEST_REGS)
{
	LARGE_INTEGER tsc;
	tsc.QuadPart = __rdtsc();
	g_GUEST_REGS->rdx = tsc.HighPart;
	g_GUEST_REGS->rax = tsc.LowPart;
	
}
VOID DealRDTSCP(PGUEST_REGS g_GUEST_REGS) 
{
	LARGE_INTEGER tsc;
	UINT64 aux = 0;
	tsc.QuadPart = __rdtscp(&aux);
	g_GUEST_REGS->rdx = tsc.HighPart;
	g_GUEST_REGS->rax = tsc.LowPart;
	g_GUEST_REGS->rcx = aux;

}
VOID DealXSETBV(PGUEST_REGS g_GUEST_REGS)
{
	
	LARGE_INTEGER bv;
	bv.HighPart = (ULONG32)g_GUEST_REGS->rdx;
	bv.LowPart = (ULONG32)g_GUEST_REGS->rax;
	_xsetbv((ULONG32)g_GUEST_REGS->rcx,bv.QuadPart);

}
VOID DealINVD()
{
	vmx_invd();
	
}
VOID HandleExitRIPRFL(ULONG CpuNumber,ULONG64 RFlags)
{
	if (CVVMX_State[CpuNumber].NeedIncRip == TRUE)
	{
		ULONG64 instructionlen = vmx_vmread(VMCS_INSTRUCTION_LENGH);
		__vmx_vmwrite(VMCS_GUSTAREA_RIP, vmx_vmread(GUEST_RIP) + instructionlen);
		__vmx_vmwrite(VMCS_GUSTAREA_RFLAGS, RFlags);
	}
	if (!CVVMX_State[CpuNumber].isstopvt)
	{
		__vmx_vmwrite(VMCS_GUSTAREA_RFLAGS, RFlags);
	}
	
}
VOID DealEPTVIOLATION(ULONG CpuNumber)
{
	ULONG64 guest_phy_address = vmx_vmread(GUEST_PHYSICAL_ADDRESS);
	ULONG64 guest_linear_address = vmx_vmread(GUEST_LINEAR_ADDRESS);
	ULONG64 Exit_Qualification = vmx_vmread(VMCS_EXIT_QUALIFICTION);
	P_EPT_QULIFICATION_TABLE pEPT_QULIFICATION = (P_EPT_QULIFICATION_TABLE)&Exit_Qualification;
	DbgPrintLog("[+] Trigger EPT VIOLATION At VIRTUAL ADDRESS %llx\n", guest_linear_address)
	DbgPrintLog("[+] EPT VIOLATION At PHYSICAL ADDRESS %llx\n", guest_phy_address)
	DbgPrintLog("[+] EPT VIOLATION ACCESS REASON: read=%llx,write=%llx,exec=%llx\n", pEPT_QULIFICATION->Read, pEPT_QULIFICATION->Write, pEPT_QULIFICATION->Execute);
	if (!HandleEPTPageHook(pEPT_QULIFICATION, guest_phy_address))
	{
		DbgPrintLog("[!] Error: HandleEPTPageHook ERROR\n");
	} 
	CVVMX_State[CpuNumber].NeedIncRip = FALSE;
}
VOID DealExceptionInject(ULONG CpuNumber)
{
	DbgBreakPoint();
	VMEXIT_INTERRUPT_INFO interruptinfo;
	interruptinfo.all =(UINT32)vmx_vmread(VM_EXIT_INTR_INFO);
	if (interruptinfo.Bits.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION && interruptinfo.Bits.Vector == EXCEPTION_VECTOR_DIVIDE_ERROR)
	{
		UINT32 errorcode = vmx_vmread(VM_EXIT_INTR_ERROR_CODE);
		InterruptEventInject(INTERRUPT_TYPE_HARDWARE_EXCEPTION, EXCEPTION_VECTOR_DIVIDE_ERROR, FALSE, errorcode);
		
	}
	CVVMX_State[CpuNumber].NeedIncRip = FALSE;
}

BOOLEAN VmhostEntrydbg(PGUEST_REGS g_GUEST_REGS)
{

	ULONG64 exitreason = vmx_vmread(VM_EXIT_REASON);
	ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
	ULONG64 grsp = vmx_vmread(GUEST_RSP);
	ULONG64 grip = vmx_vmread(GUEST_RIP);
	ULONG64 grflags = vmx_vmread(VMCS_GUSTAREA_RFLAGS);
	CVVMX_State[CpuNumber].NeedIncRip = TRUE;
	switch (exitreason)
	{
	case EXIT_REASON_CR_ACCESS:
		
		DealCrReg(g_GUEST_REGS);       //cr access
		break;

	case EXIT_REASON_CPUID:             //cpuid
		DealCPUID(g_GUEST_REGS);
		break;

	case EXIT_REASON_RDTSC:                //rdtsc
		DealRDTSC(g_GUEST_REGS); 
		break;

	case EXIT_REASON_VMCALL:
		DealVmcall(g_GUEST_REGS->rcx,g_GUEST_REGS->rdx,g_GUEST_REGS->r8,g_GUEST_REGS->r9);
		break;

	case EXIT_REASON_MSR_READ:            //rdmsr
		DealRDMSR(g_GUEST_REGS);
		break;

	case EXIT_REASON_MSR_WRITE:             //writemsr
		DealWRMSR(g_GUEST_REGS);
		break;

	case EXIT_REASON_INVD:
		vmx_invd();
		break;

	case EXIT_REASON_RDTSCP:              //rdtscp
		DealRDTSCP(g_GUEST_REGS);
		break;

	case EXIT_REASON_XSETBV:               //xsetbv
		DealXSETBV(g_GUEST_REGS);
		break;

	case EXIT_REASON_EPT_VIOLATION:
		DealEPTVIOLATION(CpuNumber);
		break;

	case EXIT_REASON_EXCEPTION_NMI:
		DealExceptionInject(CpuNumber);
		break;

	default:
		DbgPrintLog("exitreason: %x\n", exitreason);
		DbgPrintLog("grip %llx: \n", grip);
		DbgPrintLog("grsp %llx: \n", grsp);
		DbgBreakPoint();
		break;
	}
	HandleExitRIPRFL(CpuNumber, grflags);
	return CVVMX_State[CpuNumber].isstopvt;

}
