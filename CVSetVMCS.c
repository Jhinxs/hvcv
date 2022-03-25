#include "CVSetVMCS.h"
#include "selector.h"
#include "CVGlobalVaribles.h"
#include "CVvmexitEntry.h"
#include "CVEpt.h"


NTSTATUS CVSetUpVMXCS(ULONG64 GuestStack)
{
    

    ULONG CpuNumber = KeGetCurrentProcessorNumberEx(NULL);
    SEGMENT_SELECTOR SegmentSelector;

    ULONG64 GdtBase = vmx_GetGdtBase();
    
    //1. vmwrite host area
    __vmx_vmwrite(VMCS_HOSTAREA_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOSTAREA_CR3, VMM_CR3);
    __vmx_vmwrite(VMCS_HOSTAREA_CR4, __readcr4());
    __vmx_vmwrite(VMCS_HOSTAREA_CS, readcs() & 0xf8);
    __vmx_vmwrite(VMCS_HOSTAREA_DS, readds() & 0xf8);
    __vmx_vmwrite(VMCS_HOSTAREA_ES, reades() & 0xf8);
    __vmx_vmwrite(VMCS_HOSTAREA_SS, readss() & 0xf8);

    __vmx_vmwrite(VMCS_HOSTAREA_FS, readfs() & 0xf8);
    __vmx_vmwrite(VMCS_HOSTAREA_GS, readgs() & 0xf8);
    __vmx_vmwrite(VMCS_HOSTAREA_TR, readtr() & 0xf8);
    __vmx_vmwrite(VMCS_HOSTAREA_GDTR_BASE, vmx_GetGdtBase());
    __vmx_vmwrite(VMCS_HOSTAREA_IDTR_BASE, vmx_GetIdtBase());
    __vmx_vmwrite(VMCS_HOSTAREA_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(VMCS_HOSTAREA_GS_BASE, __readmsr(MSR_GS_BASE));;
    InitializeSegmentSelector(&SegmentSelector, readtr(), GdtBase);
    __vmx_vmwrite(VMCS_HOSTAREA_TR_BASE, SegmentSelector.base);


    __vmx_vmwrite(VMCS_HOSTAREA_IA32_EFER, __readmsr(MSR_IA32_EFER));

    __vmx_vmwrite(VMCS_HOSTAREA_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOSTAREA_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOSTAREA_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_HOSTAREA_RSP, ((ULONG64)CVVMX_State[CpuNumber].VMhost_Stack) + VMM_STACK_SIZE -1);
    __vmx_vmwrite(VMCS_HOSTAREA_RIP, (ULONG64)vmx_vmmhostentry);
    //2. vmwrite guest area

    __vmx_vmwrite(VMCS_GUSTAREA_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUSTAREA_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUSTAREA_CR4, __readcr4());
    __vmx_vmwrite(VMCS_GUSTAREA_DR7, 0x400);
    __vmx_vmwrite(VMCS_GUSTAREA_RSP, GuestStack);
    __vmx_vmwrite(VMCS_GUSTAREA_RIP, (ULONG64)VMXRestoreRegState);
    __vmx_vmwrite(VMCS_GUSTAREA_RFLAGS, __readeflags());
    FillGuestSelectorData(GdtBase, CS, readcs());
    FillGuestSelectorData(GdtBase, DS, readds());
    FillGuestSelectorData(GdtBase, ES, reades());
    FillGuestSelectorData(GdtBase, FS, readfs());
    FillGuestSelectorData(GdtBase, GS, readgs());
    FillGuestSelectorData(GdtBase, SS, readss());
    FillGuestSelectorData(GdtBase, TR, readtr());
    FillGuestSelectorData(GdtBase, LDTR, vmx_GetLdtr());

    //__vmx_vmwrite(VMCS_GUSTAREA_CS_BASE, 0);
    //__vmx_vmwrite(VMCS_GUSTAREA_DS_BASE, 0);
    //__vmx_vmwrite(VMCS_GUSTAREA_ES_BASE, 0);
    //__vmx_vmwrite(VMCS_GUSTAREA_SS_BASE, 0);
    __vmx_vmwrite(VMCS_GUSTAREA_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(VMCS_GUSTAREA_GS_BASE, __readmsr(MSR_GS_BASE));


    __vmx_vmwrite(VMCS_GUSTAREA_LINKPOINT_FULL, 0XFFFFFFFF);
    __vmx_vmwrite(VMCS_GUSTAREA_LINKPOINT_HIGH, 0XFFFFFFFF);

    __vmx_vmwrite(VMCS_GUSTAREA_GDTR_BASE, vmx_GetGdtBase());
    __vmx_vmwrite(VMCS_GUSTAREA_GDTR_LIMT, vmx_GetGdtLimit());
    __vmx_vmwrite(VMCS_GUSTAREA_IDTR_BASE, vmx_GetIdtBase());
    __vmx_vmwrite(VMCS_GUSTAREA_IDTR_LIMT, vmx_GetIdtLimit());

    __vmx_vmwrite(VMCS_GUSTAREA_DEBUGCTL_FULL, __readmsr(MSR_IA32_DEBUGCTL));
    __vmx_vmwrite(VMCS_GUSTAREA_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

    __vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUSTAREA_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(VMCS_GUSTAREA_ACTIVITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUSTAREA_INTERRUPTIBILITY_INFO, 0);
    __vmx_vmwrite(VMCS_GUSTAREA_IA32_EFER, __readmsr(MSR_IA32_EFER));
    ////3. vmwrite control area
    //   //3.1  vm-execution controle fields
    __vmx_vmwrite(VMCS_PIN_BASE_CONTROL, AdjustControlBit(0, MSR_IA32_VMX_PINBASED_CTLS));

    ULONG64 Interceptions = 0;
    Interceptions = AdjustControlBit(0, MSR_IA32_VMX_PROCBASED_CTLS);
    Interceptions |= VM_EXIT_RDTSC_EXIT;
    Interceptions |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
    Interceptions |= CPU_BASED_ACTIVATE_MSR_BITMAP;
    __vmx_vmwrite(VMCS_PROCESSOR_BASE_CONTTOL, Interceptions);

    Interceptions = 0;
    Interceptions = AdjustControlBit(0, MSR_IA32_VMX_SECPROCBASED_CTLS2);
    Interceptions |= VM_EXIT_INVPCID;
    Interceptions |= VM_EXIT_ENABLE_RDTSCP;
    Interceptions |= VM_EXIT_XSAVE_OR_XSTORS;

    if (Global_CVEnableEPT && CVVMX_State[CpuNumber].InitEPT && pEptState->EptPointer.all !=0)
    {       
            Interceptions |= VM_SECONDARY_EXEC_ENABLE_EPT;
            Interceptions |= VM_SECONDARY_EXEC_ENABLE_VPID;
            __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, Interceptions);
            __vmx_vmwrite(VIRTUAL_PROCESSOR_ID, VPIDTAG);
            __vmx_vmwrite(EPT_POINTER, pEptState->EptPointer.all);
            DbgPrintLog("[+] Enable EPT On CPU[%d]\n", CpuNumber);
    }
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, Interceptions);
     __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
     __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
    __vmx_vmwrite(TSC_OFFSET, 0);
    __vmx_vmwrite(TSC_OFFSET_HIGH, 0);

    __vmx_vmwrite(CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE3, 0);

    __vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);

    __vmx_vmwrite(CR0_READ_SHADOW, 0);
    __vmx_vmwrite(CR4_READ_SHADOW, 0);

    __vmx_vmwrite(MSR_BITMAP, CVVMX_State[CpuNumber].MsrBitMapPhyAddress);

  //  __vmx_vmwrite(EXCEPTION_BITMAP, 1 << EXCEPTION_VECTOR_DIVIDE_ERROR);  //用于测试异常事件注入，除0异常
    //   //3.2  vm-entry controle fields 
    __vmx_vmwrite(VMCS_VM_ENTRY_CONTROL, AdjustControlBit(VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_IA32_EFER, MSR_IA32_VMX_ENTRY_CTLS));
    __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
    //3.2  vm-exit controle fields  
    __vmx_vmwrite(VMCS_VM_EXIT_CONTROL, AdjustControlBit(VM_EXIT_IA32E_MODE | VM_EXIT_LOAD_IA32_EFER | VM_EXIT_SAVE_IA32_EFER | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);

     //4. vmwrite exit information area 
    DbgPrintLog("[+] VMCS Setup Over On CPU[%d]\n", KeGetCurrentProcessorNumberEx(NULL));

    __vmx_vmlaunch();                                                     //11.进入VT
    CVVMX_State[CpuNumber].isstartvt = FALSE;
    
    DbgPrintLog("vm launch error: %x\n", vmx_vmread(VM_INSTRUCTION_ERROR));
    return STATUS_SUCCESS;
}
ULONG64 AdjustControlBit(ULONG64 uRetVaule, ULONG64 msr)
{

    LARGE_INTEGER MsrVaule;
    MsrVaule.QuadPart = __readmsr(msr);
    uRetVaule &= MsrVaule.HighPart;
    uRetVaule |= MsrVaule.LowPart;
    return uRetVaule;
}