#pragma once
#include "CVEpt.h"
#include "CVGlobalVaribles.h"
#include "CVvmcall.h"
#include "ssdt.h"

BOOLEAN CVInitEPT()
{
    if (!Global_CVEnableEPT)
    {
        return FALSE;
    }
    KIRQL irql;
    ULONG CpuNumber  = KeGetCurrentProcessorNumberEx(NULL);
    for (int i = 0; i < CpuNumber; i++)
    {
        CVVMX_State[i].InitEPT = FALSE;
    }
    IA32_MTRR_DEF_TYPE_Reg mtrrdef = { 0 };
    IA32_EPT_VPID_CAP_BITS EPTVPID = { 0 };
    mtrrdef.all = __readmsr(MSR_IA32_MTRR_DEF_TYPE);
    EPTVPID.all = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
    ULONG64 ept_bit = __readmsr(MSR_IA32_VMX_SECPROCBASED_CTLS2);
    if (!((ept_bit & 0x200000000) == 0x200000000))        //MSR_IA32_VMX_SECPROCBASED_CTLS2[33]=1 support ept
    {
        return FALSE;
    }

    if (!(EPTVPID.Bits.PageWalkLength4 && EPTVPID.Bits.Pde2MbPages && EPTVPID.Bits.MemoryTypeWriteBack))
    {
        return FALSE;
    }
    if (!EPTVPID.Bits.AdvancedVmexitEptViolationsInformation)
    {
        return FALSE;
    }
    if (!EPTVPID.Bits.Invvpid)
    {
        DbgPrintLog("[+] CPU[%d] Not Support VPID\n", CpuNumber);
    }
    if (!mtrrdef.Bits.MtrrEnable)
    {
        DbgPrintLog("[!] Mtrr Do not Support\n");
        return FALSE;
    }
    DbgPrintLog("[+] CPU Core Support EPT\n");
    pEptState = ExAllocatePoolWithTag(NonPagedPool, sizeof(EPT_STATE), 'epts');

    RtlSecureZeroMemory(pEptState, sizeof(EPT_STATE));

    if (!CVBuildMtrrMap())
    {
        DbgPrintLog("[!] Error: Mtrr Build Failed\n");
        return FALSE;
    }
    if (pEptState == NULL)
    {
        return FALSE;
    }
   
    if (!CVEptMemeoryInit())
    {
        DbgPrintLog("[!] Error: EPT Table Build Failed\n");
        return FALSE;
    }
    InitializeListHead(&pEptState->DynamicSplitPoolList);
    InitializeListHead(&pEptState->FakePagePoolList);
    InitializeListHead(&pEptState->FakePageList);
    KeInitializeSpinLock(&GLock);
    KeAcquireSpinLock(&GLock, &irql);
    InitlizePagePoolForHook(3);              //hook count 3 ，其实并没测试过HOOK多个
    KeReleaseSpinLock(&GLock, irql);
    return TRUE;
}
BOOLEAN CVBuildMtrrMap()
{
    IA32_MTRR_CAPABILITIES_REGISTER MTRRCap;
    IA32_MTRR_PHYSBASE_REGISTER CurrentPhysBase;
    IA32_MTRR_PHYSMASK_REGISTER CurrentPhysMask;
    PMTRR_RANGE_DESCRIPTOR Descriptor;
    ULONG NumberOfBitsInMask;
    MTRRCap.all = __readmsr(MSR_IA32_MTRR_CAPABILITIES);
    for (int i = 0; i < MTRRCap.Bits.VariableRangeCount; i++)
    {
        CurrentPhysBase.all = __readmsr(MSR_IA32_MTRR_PHYSBASE0 + (i * 2));
        CurrentPhysMask.all = __readmsr(MSR_IA32_MTRR_PHYSMASK0 + (i * 2));
        if (CurrentPhysMask.Bits.Valid)
        {
            Descriptor = &pEptState->MemoryRanges[pEptState->NumberOfEnabledMemoryRanges++];
            Descriptor->PhysBaseAddress = CurrentPhysBase.Bits.PhysBase * PAGE_SIZE;
            _BitScanForward64(&NumberOfBitsInMask, CurrentPhysMask.Bits.PhysMask * PAGE_SIZE);
            Descriptor->PhysEndAddress = Descriptor->PhysBaseAddress + ((1ULL << NumberOfBitsInMask) - 1ULL);
            Descriptor->MemoryType = (UCHAR)CurrentPhysBase.Bits.Type;
            Descriptor->enable = CurrentPhysMask.Bits.Valid;
            if (Descriptor->MemoryType == MEMORY_TYPE_WRITE_BACK)
            {
                pEptState->NumberOfEnabledMemoryRanges--;
            }
            DbgPrintLog("[+] MTRR Range: Base=0x%llx End=0x%llx Type=0x%x\n", Descriptor->PhysBaseAddress, Descriptor->PhysEndAddress, Descriptor->MemoryType);
        }
       

    }
    DbgPrintLog("[+] MTRR Build Over\n");
    DbgPrintLog("[+] MTRR Ranges: %d\n", pEptState->NumberOfEnabledMemoryRanges);
    return TRUE;
}

BOOLEAN CVEptMemeoryInit() 
{
    
    PHYSICAL_ADDRESS eptsize;
    eptsize.QuadPart = MAXULONG64;
    PageTable = MmAllocateContiguousMemory(sizeof(VMM_EPT_PAGE_TABLE), eptsize);
    
    if (PageTable == NULL)
    {
        return FALSE;
    }
    pEptState->EptPageTable = PageTable;
    PageTable->PML4[0].all = 0;
    PageTable->PML4[0].Bits.read_access = 1;
    PageTable->PML4[0].Bits.write_access = 1;
    PageTable->PML4[0].Bits.exec_access_supervisor = 1;
    PageTable->PML4[0].Bits.PDPTPFN = MmGetPhysicalAddress(&PageTable->PML3[0]).QuadPart >> 12;

    for (int i = 0; i < VMM_EPT_PML3E_COUNT; i++)
    {
        PageTable->PML3[i].all = 0;
        PageTable->PML3[i].Bits.read_access = 1;
        PageTable->PML3[i].Bits.write_access = 1;
        PageTable->PML3[i].Bits.exec_access_supervisor = 1;
        PageTable->PML3[i].Bits.PDTPFN = MmGetPhysicalAddress(&PageTable->PML2[i][0]).QuadPart >> 12;

    }
    for (int i = 0; i < VMM_EPT_PML3E_COUNT; i++)
    {
        for (int j = 0; j < VMM_EPT_PML2E_COUNT; j++)
        {
            PageTable->PML2[i][j].all = 0;
            PageTable->PML2[i][j].Bits.ExecuteAccess = 1;
            PageTable->PML2[i][j].Bits.ReadAccess = 1;
            PageTable->PML2[i][j].Bits.WriteAccess = 1;
            PageTable->PML2[i][j].Bits.LargePage = 1;
            PageTable->PML2[i][j].Bits.PhyPagePFN = (i * VMM_EPT_PML2E_COUNT) + j;
            SetMemMtrrInfo(PageTable->PML2[i][j], (i * VMM_EPT_PML2E_COUNT) + j);
        }

    }
    if (!SetEptpointer(PageTable))
    {
        return FALSE;
    }
  
    DbgPrintLog("[+] EPT Init Success !\n");
    return TRUE;

}
VOID SetMemMtrrInfo(EPT_PML2_M_ENTRY pde_2M, ULONG64 phyaddr)
{
    ULONG64 pageaddress = phyaddr * LargePage_Size;
    ULONG64 memorytype_mtrr = MEMORY_TYPE_WRITE_BACK;
    if (phyaddr == 0)
    {
        pde_2M.Bits.MemoryType = MEMORY_TYPE_UNCACHEABLE;
        return;
    }
    for (int i = 0; i < pEptState->NumberOfEnabledMemoryRanges; i++)
    {
        if (pEptState->MemoryRanges[i].enable)
        {

            if (pageaddress <= pEptState->MemoryRanges[i].PhysEndAddress)
            {
                if (pageaddress + LargePage_Size - 1 >= pEptState->MemoryRanges[i].PhysBaseAddress)
                {
                    memorytype_mtrr = pEptState->MemoryRanges[i].MemoryType;
                    if (memorytype_mtrr == MEMORY_TYPE_UNCACHEABLE)
                    {
                        break;
                    }
                }
            }
        }
    }
    pde_2M.Bits.MemoryType = memorytype_mtrr;
}
BOOLEAN SetEptpointer(PVMM_EPT_PAGE_TABLE pml4addr)
{
   
    EPTPointer eptp = { 0 };
    EptVpidCapMsr vpidcap = { 0 };
    vpidcap.all = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
    if (vpidcap.Bits.support_page_walk_length4)
    {
        eptp.Bits.walk_length = 3;
    }
    if (vpidcap.Bits.support_uncacheble_memory_type)
    {
        eptp.Bits.memory_type = MEMORY_TYPE_UNCACHEABLE;
    }
    if (vpidcap.Bits.support_write_back_memory_type)
    {
        eptp.Bits.memory_type = MEMORY_TYPE_WRITE_BACK;
    }
    if (vpidcap.Bits.support_accessed_and_dirty_flag)
    {
        eptp.Bits.dirty_access_flag = 1;
    }
    else
    {
        eptp.Bits.dirty_access_flag = 0;
    }
    
    eptp.Bits.pml4t_address = MmGetPhysicalAddress(&pml4addr->PML4).QuadPart >> 12;
    pEptState->EptPointer = eptp;
    DbgPrintLog("[+] EPTP Set Over | EptPointer: %llx\n", pEptState->EptPointer.all);
    return TRUE;
}
PPDE_2MB EptGetPDE2MBENTRY(PVMM_EPT_PAGE_TABLE EptPageTable, ULONG64 phy) 
{
    PPDE_2MB PPDE2MB;
    ULONG64 PML4T_INDEX, PDPT_INDEX, PDT_INDEX;
    PDT_INDEX = ADDRMASK_EPT_PML2_INDEX(phy);
    PDPT_INDEX = ADDRMASK_EPT_PML3_INDEX(phy);
    PML4T_INDEX = ADDRMASK_EPT_PML4_INDEX(phy);
    if (PML4T_INDEX > 0)
    {
        return NULL;
    }
    PPDE2MB = &EptPageTable->PML2[PDPT_INDEX][PDT_INDEX];
    return PPDE2MB;
}

PPTE EptGetPTEENTRY(PVMM_EPT_PAGE_TABLE EptPageTable, ULONG64 phy) 
{
    PPDE_2MB PPDE2MB;
    PPDE PPDE4K;
    PPTE PTE4K;
    ULONG64 PML4T_INDEX, PDPT_INDEX, PDT_INDEX;
    PHYSICAL_ADDRESS phyaddr;
    phyaddr.QuadPart = MAXULONG64;
    PDT_INDEX = ADDRMASK_EPT_PML2_INDEX(phy);
    PDPT_INDEX = ADDRMASK_EPT_PML3_INDEX(phy);
    PML4T_INDEX = ADDRMASK_EPT_PML4_INDEX(phy);
    if (PML4T_INDEX > 0)
    {
        return NULL;
    }
    PPDE2MB = &EptPageTable->PML2[PDPT_INDEX][PDT_INDEX];
    if (PPDE2MB->Bits.LargePage)
    {
        return NULL;
    }
    PPDE4K = (PPDE)(PPDE2MB);

    phyaddr.QuadPart = PPDE4K->Bits.PTTPFN * PAGE_SIZE;
    PTE4K = (PPTE)MmGetVirtualForPhysical(phyaddr);
    if (PTE4K==NULL)
    {
        return NULL;
    }
    PTE4K = &PTE4K[ADDRMASK_EPT_PML1_INDEX(phy)];
}
BOOLEAN EptSplit2Mto4K(PVMM_EPT_PAGE_TABLE EptPageTable, ULONG64 PhysicalAddress, ULONG ProcessNum)
{
    PVMM_EPT_DYNAMIC_SPLIT split;
    PDE NewPTE = {0};
    PPDE_2MB largepage = EptGetPDE2MBENTRY(EptPageTable, PhysicalAddress);
    if (largepage == NULL)
    {
        DbgPrintLog("Error: Get PDE2MB Entry Failed\n");
        return FALSE;
    }
    if (!largepage->Bits.LargePage)
    {
        return TRUE;
    }
    split = MallocSplitPageFromPagePoolList();              //从提前分配好的内存池中分配一块内存，vmx root mode IRQL较高 NT 分配内存较大概率拉跨
    if (split == NULL)
    {
        DbgPrintLog("Error: SplitBuffer Failed\n");
        return FALSE;
    }
    CVVMX_State[ProcessNum].Splitbuffer = split;
    split->Entry = largepage;
    for (int i = 0; i < VMM_EPT_PML1E_COUNT; i++)
    {
        split->PML1[i].all = 0;
        split->PML1[i].Bits.read_access = 1;
        split->PML1[i].Bits.write_access = 1;
        split->PML1[i].Bits.exec_access_supervisor = 1;
        split->PML1[i].Bits.PhyPagePFN = largepage->Bits.PhyPagePFN * LargePage_Size / PAGE_SIZE + i;
    }
    NewPTE.all = 0;
    NewPTE.Bits.exec_access_supervisor = 1;
    NewPTE.Bits.read_access = 1;
    NewPTE.Bits.write_access = 1;
    NewPTE.Bits.PTTPFN = (ULONG64)MmGetPhysicalAddress(&split->PML1[0]).QuadPart / PAGE_SIZE;
    RtlCopyMemory(largepage, &NewPTE, sizeof(NewPTE));
    
    return TRUE;
}
BOOLEAN HandleEPTPageHook(P_EPT_QULIFICATION_TABLE PQ, ULONG64 phy) 
{
    
     ULONG64 phyalign = PAGE_ALIGN(phy);
     PPTE hookpagepte = EptGetPTEENTRY(pEptState->EptPageTable, phyalign);
     if (hookpagepte == NULL)
     {
        DbgPrintLog("[!] Error: Try To Get PTE of hookpage Failed\n");
        return FALSE;
     }
     /// <summary>
     PEPT_FAKE_PAGE fake_page = GetFakePage(phy);
     if (fake_page ==NULL)
     {
         DbgPrintLog("[!] Error: Try To Fake Page For Hookitem Failed\n");
         return FALSE;
     }

     if (!PQ->ExecuteAble && PQ->Execute)
     {
         fake_page->OriginalEntryAddress->all = fake_page->FakeEntryForX.all;
         InveptSingleContext(pEptState->EptPointer.all);
         DbgPrintLog("[+] Set hookpage PFN = %llx exec access to 1\n", hookpagepte->Bits.PhyPagePFN);
         return TRUE;
     }
     if (PQ->ExecuteAble && (PQ->Read|PQ->Write))
     {
         fake_page->OriginalEntryAddress->all = fake_page->FakeEntryForRW.all;
         InveptSingleContext(pEptState->EptPointer.all);
         DbgPrintLog("[+] Set hookpage PFN = %llx read access to 1,write access to 1\n", hookpagepte->Bits.PhyPagePFN);
         return TRUE;
     }
    /// <summary>
    return FALSE;
}
PEPT_FAKE_PAGE GetFakePage(ULONG64 phy) 
{
  
    PLIST_ENTRY list = &pEptState->FakePageList;
    while (list->Flink != &pEptState->FakePageList)
    {
        PEPT_FAKE_PAGE fakepagepool = (PEPT_FAKE_PAGE)CONTAINING_RECORD(list->Flink, EPT_FAKE_PAGE, POOL_LIST);
        if (fakepagepool->PhyPFN == phy>>12)
        {
            return fakepagepool;
        }
        list = list->Flink;
    }
    return NULL;


}

PEPT_FAKE_PAGE MallocFakePageFromPagePoolList()
{
    PLIST_ENTRY list = &pEptState->FakePagePoolList;
    while (list->Flink != &pEptState->FakePagePoolList)
    {
        PEPT_FAKE_PAGE_POOL fakepagepool = (PEPT_FAKE_PAGE_POOL)CONTAINING_RECORD(list->Flink, EPT_FAKE_PAGE_POOL, POOL_LIST);
        if (fakepagepool->IsUsed == FALSE)
        {
            fakepagepool->IsUsed = TRUE;
            return fakepagepool->eptfakepage;
        }
        list = list->Flink;
    }
    return NULL;

}


PVMM_EPT_DYNAMIC_SPLIT MallocSplitPageFromPagePoolList()
{
    
    PLIST_ENTRY list = &pEptState->DynamicSplitPoolList;
    while (list->Flink != &pEptState->DynamicSplitPoolList)
    {
        PVMM_EPT_DYNAMIC_SPLIT_POOL dynamic_split_pool = (PVMM_EPT_DYNAMIC_SPLIT_POOL)CONTAINING_RECORD(list->Flink, VMM_EPT_DYNAMIC_SPLIT_POOL, POOL_LIST);
        if (dynamic_split_pool->IsUsed == FALSE)
        {
            dynamic_split_pool->IsUsed = TRUE;
            return dynamic_split_pool->dynamicsplit;
        }
        list = list->Flink;
    }
    return NULL;
}
VOID InitlizePagePoolForHook(int count)
{

    for (int i = 0; i < count; i++)
    {

        PVMM_EPT_DYNAMIC_SPLIT_POOL dynamic_split_pool = (PVMM_EPT_DYNAMIC_SPLIT_POOL)ExAllocatePool(NonPagedPool, sizeof(VMM_EPT_DYNAMIC_SPLIT_POOL));
        PVMM_EPT_DYNAMIC_SPLIT dynamic_split = (PVMM_EPT_DYNAMIC_SPLIT)ExAllocatePool(NonPagedPool, sizeof(VMM_EPT_DYNAMIC_SPLIT));
        RtlZeroMemory(dynamic_split_pool, sizeof(VMM_EPT_DYNAMIC_SPLIT_POOL));
        RtlZeroMemory(dynamic_split, sizeof(VMM_EPT_DYNAMIC_SPLIT));
        dynamic_split_pool->dynamicsplit = dynamic_split;
        dynamic_split_pool->IsUsed = FALSE;

        InsertHeadList(&pEptState->DynamicSplitPoolList, &dynamic_split_pool->POOL_LIST);

        PEPT_FAKE_PAGE_POOL fakepagepool = (PEPT_FAKE_PAGE_POOL)ExAllocatePool(NonPagedPool, sizeof(EPT_FAKE_PAGE_POOL));
        PEPT_FAKE_PAGE fakepage = (PEPT_FAKE_PAGE)ExAllocatePool(NonPagedPool, sizeof(EPT_FAKE_PAGE));
        RtlZeroMemory(fakepagepool, sizeof(EPT_FAKE_PAGE_POOL));
        RtlZeroMemory(fakepage, sizeof(EPT_FAKE_PAGE));
        fakepagepool->eptfakepage = fakepage;
        fakepagepool->IsUsed = FALSE;
        InsertHeadList(&pEptState->FakePagePoolList, &fakepagepool->POOL_LIST);
    }
}
VOID FreeEPTHOOKPagePool() 
{
    KIRQL irql;
    KeAcquireSpinLock(&GLock, &irql);
    PLIST_ENTRY list = &pEptState->FakePagePoolList;
    while (list->Flink != &pEptState->FakePagePoolList)
    {
        PEPT_FAKE_PAGE_POOL fakepagepool = (PEPT_FAKE_PAGE_POOL)CONTAINING_RECORD(list->Flink, EPT_FAKE_PAGE_POOL, POOL_LIST);
       
        if (fakepagepool)
        {
            if (fakepagepool->eptfakepage->HookBytes)
            {
                ExFreePool(fakepagepool->eptfakepage->HookBytes);
            }
            ExFreePool(fakepagepool);
        }
        list = list->Flink;
    }
    list = &pEptState->DynamicSplitPoolList;
    while (list->Flink != &pEptState->DynamicSplitPoolList)
    {
        PVMM_EPT_DYNAMIC_SPLIT_POOL dynamic_split_pool = (PVMM_EPT_DYNAMIC_SPLIT_POOL)CONTAINING_RECORD(list->Flink, VMM_EPT_DYNAMIC_SPLIT_POOL, POOL_LIST);
        if (dynamic_split_pool)
        {
            if (dynamic_split_pool->dynamicsplit)
            {
                ExFreePool(dynamic_split_pool->dynamicsplit);
            }
            ExFreePool(dynamic_split_pool);
        }
        list = list->Flink;
    }
    KeReleaseSpinLock(&GLock, irql);
}

VOID FreeEPT() 
{
    if (!Global_CVEnableEPT)
    {
        return;
    }
    if (EnbaleHook)
    {
        FreeEPTHOOKPagePool();
    }
    MmFreeContiguousMemory(PageTable);
    ExFreePoolWithTag(pEptState, 'epts');
    DbgPrintLog("[+] Free Ept Mem Over\n");
}