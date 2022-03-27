#pragma once
#include "CVvmutil.h"
#include "CVGlobalVaribles.h"
#include "CVDpc.h"
#include "CVvmexitEntry.h"
#include "CVEpt.h"
#include "CVvmcall.h"
#include "hook.h"
#include "SSDT.h"

BOOLEAN CVInitialize() 
{
    if (!CVCheakVTSupport())
    {
        return FALSE;
    }
    ULONG processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    CVVMX_State = ExAllocatePoolWithTag(NonPagedPool, sizeof(VMX_CPU) * processors, 'vmx');
    if (CVVMX_State == NULL)
    {
        DbgPrintLog("[!] Error: VMX_State Memory Allocate Failed\n");
        return FALSE;
    }
    RtlSecureZeroMemory(CVVMX_State, sizeof(VMX_CPU) * processors);
    KeGenericCallDpc(CVVMXRegionsAllocate, NULL);
    KeGenericCallDpc(CVVMMAllocateMem, NULL);
    KeGenericCallDpc(CVVMXAllocateMsrBitMap, NULL);

    if (CVInitEPT())
    {
        for (int CpuNumber = 0; CpuNumber < processors; CpuNumber++)
        {
            CVVMX_State[CpuNumber].InitEPT = TRUE;
        }
        if (EnbaleHook)
        {
            CVSet_EPT_PAGE_HOOK((PVOID)GetNTAPIAddress(), (PVOID)NtTerminateProcessHook, (PVOID*)&NtTerminateProcessRetOrig, FALSE);
        }
    }
    return TRUE;
}

BOOLEAN CVVMMAllocateMem(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{   

    PHYSICAL_ADDRESS physvmm;
    physvmm.QuadPart = MAXULONG64;
    ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
    CVVMX_State[CpuNumber].VMhost_Stack = MmAllocateContiguousMemory(VMM_STACK_SIZE, physvmm);
    if (CVVMX_State[CpuNumber].VMhost_Stack == NULL)
    {
        DbgPrintLog("[!] Error: CPU %d vm host Stack memory Allocate Failed\n");
        return FALSE;
    }
    RtlSecureZeroMemory(CVVMX_State[CpuNumber].VMhost_Stack, VMM_STACK_SIZE);
    DbgPrintLog("[+] CPU[%d] VMHost_Stack %llx\n", CpuNumber, CVVMX_State[CpuNumber].VMhost_Stack);
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
    return TRUE;
}

BOOLEAN CVVMXRegionsAllocate(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) 
{
    ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
    PHYSICAL_ADDRESS physvmxon;
    physvmxon.QuadPart = MAXULONG64;
    PHYSICAL_ADDRESS physvmcs;
    physvmcs.QuadPart = MAXULONG64;
    ULONG64 VMX_Basic_MSR;
    ULONG64 EFlags;
    ULONG64 cr4;
    set_cr4(X86_CR4_VMXE);
    cr4 = __readcr4();
    if ((cr4 & X86_CR4_VMXE) != X86_CR4_VMXE)
    {
        DbgPrintLog("[!] CR4_VMXE set Error \n");
        return FALSE;
    }
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();
    
    VMX_Basic_MSR = __readmsr(MSR_IA32_VMX_BASIC);                                     //获取vmcs identifier
    CVVMX_State[CpuNumber].VMXON_Region = MmAllocateContiguousMemory(PAGE_SIZE, physvmxon);
    DbgPrintLog("[+] CPU[%d] VMX_region: %llx\n", CpuNumber, CVVMX_State[CpuNumber].VMXON_Region);
    RtlSecureZeroMemory(CVVMX_State[CpuNumber].VMXON_Region, PAGE_SIZE);
    *(ULONG64*)CVVMX_State[CpuNumber].VMXON_Region = (VMX_Basic_MSR & 0x7ffffff);
    CVVMX_State[CpuNumber].VMXONRegion_PA = MmGetPhysicalAddress(CVVMX_State[CpuNumber].VMXON_Region);
    __vmx_on(&(ULONG64)(CVVMX_State[CpuNumber].VMXONRegion_PA.QuadPart));                          // vmxon 区域设置
    DbgPrintLog("[+] CPU[%d] Vmxon Success\n", CpuNumber);

    EFlags = __readeflags();
    if ((EFlags & 0x1) != 0)
    {
        DbgPrintLog("[!] VMX ERROR\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    VMX_Basic_MSR = __readmsr(MSR_IA32_VMX_BASIC);
    CVVMX_State[CpuNumber].VMXCS_Region = MmAllocateContiguousMemory(PAGE_SIZE, physvmcs);
    DbgPrintLog("[+] CPU[%d] VMXCS_Region: %llx\n", CpuNumber, CVVMX_State[CpuNumber].VMXCS_Region);
    RtlSecureZeroMemory(CVVMX_State[CpuNumber].VMXCS_Region, PAGE_SIZE);
    *(ULONG64*)CVVMX_State[CpuNumber].VMXCS_Region = (VMX_Basic_MSR & 0x7ffffff);
    CVVMX_State[CpuNumber].VMCSRegion_PA = MmGetPhysicalAddress(CVVMX_State[CpuNumber].VMXCS_Region);
    __vmx_vmclear(&CVVMX_State[CpuNumber].VMCSRegion_PA.QuadPart);                       // vmxcs区域clear
    DbgPrintLog("[+] CPU[%d] Vmcs Clear over\n", CpuNumber);

    EFlags = __readeflags();
    if ((EFlags & 0x41) != 0)
    {
        DbgPrintLog("[!] vmxcs_clear ERROR\n");
        return STATUS_UNSUCCESSFUL;
    }
    __vmx_vmptrld(&CVVMX_State[CpuNumber].VMCSRegion_PA.QuadPart);                    //初始化vmxcs working-pointer

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}
BOOLEAN CVVMXAllocateMsrBitMap(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    PHYSICAL_ADDRESS phyMsr;
    phyMsr.QuadPart = MAXULONG64;
    ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
    CVVMX_State[CpuNumber].MsrBitMapVirAddress = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'MSR');
    if (CVVMX_State[CpuNumber].MsrBitMapVirAddress == NULL)
    {
        DbgPrintLog("Error: Allocate MsrBitMap Mem Failed\n");
        return FALSE;
    }
    RtlSecureZeroMemory(CVVMX_State[CpuNumber].MsrBitMapVirAddress, PAGE_SIZE);
    CVVMX_State[CpuNumber].MsrBitMapPhyAddress = MmGetPhysicalAddress(CVVMX_State[CpuNumber].MsrBitMapVirAddress).QuadPart;
    DbgPrintLog("[+] CPU[%d] MsrBitMap Mem Allocate Success\n", CpuNumber);
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}
BOOLEAN CVCheakVTSupport() 
{
    ULONG64 ret_ecx;
    ULONG64 cr4;
    get_cpuid_info(&ret_ecx);
    if ((ret_ecx & 0X20) == 0)                 //1.检查CPU是否支持VT
    {
        return FALSE;
    }
    DWORD64 cr0 = __readcr0();
    if ((cr0 & 0x80000001) == 0)   
    {
        return FALSE;
    }
    
    cr4 = __readcr4();
    if ((cr4 & X86_CR4_VMXE) == X86_CR4_VMXE)              //CR4.VMXE 是否已开启被占用
    {

        DbgPrintLog("[!] VT is occupied by other\n");
        return FALSE;
    }


    ULONG64 msr = __readmsr(MSR_IA32_FEATURE_CONTROL);
    if (!(msr & 4))                                              //VT 指令是否被锁定
    {
        DbgPrintLog("[!] MSR_IA32_FEATURE_CONTROL VMXON Locked \n");
        return FALSE;
    }
    return TRUE;
}
BOOLEAN VMXvmshutdown() 
{
    ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
    vmx_vmcall(VMCALL_VMXOFF);
    MmFreeContiguousMemory(CVVMX_State[CpuNumber].VMXCS_Region);
    MmFreeContiguousMemory(CVVMX_State[CpuNumber].VMXON_Region);
    MmFreeContiguousMemory(CVVMX_State[CpuNumber].VMhost_Stack);
    ExFreePoolWithTag(CVVMX_State[CpuNumber].MsrBitMapVirAddress,'MSR');
    if (!CVVMX_State[CpuNumber].isstopvt)
    {
        return FALSE;
    }
    return TRUE;
}

VOID DpcInitGuestState(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) 
{
    VMXSaveRegState();
    CVVMX_State[KeGetCurrentProcessorNumberEx(NULL)].isstartvt = TRUE;
    CVVMX_State[KeGetCurrentProcessorNumberEx(NULL)].isstopvt = FALSE;
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}
VOID DpcShutSetGuestState(struct _KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) 
{
    if (!VMXvmshutdown()) 
    {
        DbgPrintLog("[!] Error: VM Shutdown On CPU[%d] Failed\n", KeGetCurrentProcessorNumberEx(NULL));
    }
    else
    {
        
        DbgPrintLog("[+] CV Simply VT Stop Successful\n");
    }
    clear_cr4(X86_CR4_VMXE);
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

ULONG64 CVReturnGuestRSP() 
{
    return CVVMX_State[KeGetCurrentProcessorNumberEx(NULL)].vmxoff_GuestRsp;
}
ULONG64 CVReturnGuestRIP() 
{
    return CVVMX_State[KeGetCurrentProcessorNumberEx(NULL)].vmxoff_GuestRip;
}

BOOLEAN CVStartVT() 
{
    Global_CVEnableEPT = FALSE;
    EnbaleHook = FALSE;
    if (!CVInitialize()) 
    {
        return FALSE;
    }
    VMM_CR3 = __readcr3();
    KeGenericCallDpc(DpcInitGuestState, NULL);
   //CVSet_EPT_PAGE_HOOK_INVM((PVOID)GetNTAPIAddress(),(PVOID)NtTerminateProcessHook, (PVOID*)&NtTerminateProcessOrig,TRUE);     //也可以在开启VT后Hook
    return TRUE;
}
VOID CVStopVT()
{
    if (EnbaleHook)
    {
        vmx_vmcall(VMCALL_REMOVE_ALLHOOK);
    }
    KeGenericCallDpc(DpcShutSetGuestState, NULL);
    ExFreePoolWithTag(CVVMX_State, 'vmx');
    FreeEPT();
}