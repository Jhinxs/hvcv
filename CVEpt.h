#pragma once
#include "common.h"

//https://rayanfam.com/topics/hypervisor-from-scratch-part-7/
// Index of the 1st paging structure (4096 byte)
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) ((_VAR_ & 0x1FF000ULL) >> 12)

// Index of the 2nd paging structure (2MB)
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) ((_VAR_ & 0x3FE00000ULL) >> 21)

// Index of the 3rd paging structure (1GB)
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) ((_VAR_ & 0x7FC0000000ULL) >> 30)

// Index of the 4th paging structure (512GB)
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) ((_VAR_ & 0xFF8000000000ULL) >> 39)

// The number of 512GB PML4 entries in the page table /
#define VMM_EPT_PML4E_COUNT 512

// The number of 1GB PDPT entries in the page table per 512GB PML4 entry.
#define VMM_EPT_PML3E_COUNT 512

// Then number of 2MB Page Directory entries in the page table per 1GB PML3 entry.
#define VMM_EPT_PML2E_COUNT 512

// Then number of 4096 byte Page Table entries in the page table per 2MB PML2 entry when dynamically split.
#define VMM_EPT_PML1E_COUNT 512


#define LargePage_Size PAGE_SIZE*512


typedef union _EPTPointer
{
	ULONG64 all;
	struct
	{
		ULONG64 memory_type : 3;
		ULONG64 walk_length : 3;
		ULONG64 dirty_access_flag : 1;
		ULONG64 reserved1 : 5;
		ULONG64 pml4t_address : 36;
		ULONG64 reserved2 : 16;
	}Bits;


} EPTPointer, * PEPTPointer;

typedef union _PML4E                    //intel system programming Vol.3C 28-1
{
	ULONG64 all;
	struct
	{
		ULONG64 read_access : 1;
		ULONG64 write_access : 1;
		ULONG64 exec_access_supervisor : 1;
		ULONG64 reserved1 : 5;
		ULONG64 accessed : 1;
		ULONG64 ignored1 : 1;
		ULONG64 exec_access_usermode : 1;
		ULONG64 ignored2 : 1;
		ULONG64 PDPTPFN : 36;
		ULONG64 reserved2 : 4;
		ULONG64 ignored3 : 12;
	}Bits;
}PML4E, * PPML4E;
static_assert(sizeof(PML4E) == sizeof(ULONG64), "PML4E Size ERROR");

typedef union _PDPTE                  //intel system programming Vol.3C 28-3
{
	ULONG64 all;
	struct
	{
		ULONG64 read_access : 1;
		ULONG64 write_access : 1;
		ULONG64 exec_access_supervisor : 1;
		ULONG64 reserved1 : 5;
		ULONG64 accessed : 1;
		ULONG64 ignored1 : 1;
		ULONG64 exec_access_usermode : 1;
		ULONG64 ignored2 : 1;
		ULONG64 PDTPFN : 36;
		ULONG64 reserved2 : 4;
		ULONG64 ignored3 : 12;
	}Bits;
}PDPTE, * PPDPTE;
static_assert(sizeof(PDPTE) == sizeof(ULONG64), "PDPTE Size ERROR");

typedef union _PDE                     //intel system programming Vol.3C 28-5
{
	ULONG64 all;
	struct
	{
		ULONG64 read_access : 1;
		ULONG64 write_access : 1;
		ULONG64 exec_access_supervisor : 1;
		ULONG64 reserved1 : 4;
		ULONG64 Zero : 1;                    //必须为0
		ULONG64 accessed : 1;
		ULONG64 ignored1 : 1;
		ULONG64 exec_access_usermode : 1;
		ULONG64 ignored2 : 1;
		ULONG64 PTTPFN : 36;
		ULONG64 reserved2 : 4;
		ULONG64 ignored3 : 12;
	}Bits;
}PDE, * PPDE;
static_assert(sizeof(PDE) == sizeof(ULONG64), "PDE Size ERROR");

typedef union _PDE_2MB
{
	struct
	{
		ULONG64 ReadAccess : 1;
		ULONG64 WriteAccess : 1;
		ULONG64 ExecuteAccess : 1;
		ULONG64 MemoryType : 3;
		ULONG64 IgnorePat : 1;
		ULONG64 LargePage : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 exec_access_usermode : 1;
		ULONG64 Reserved1 : 10;
		ULONG64 PhyPagePFN : 27;
		ULONG64 Reserved2 : 15;
		ULONG64 SuppressVe : 1;
	}Bits;

	ULONG64 all;
} PDE_2MB, *PPDE_2MB;

typedef union _PTE                         //intel system programming Vol.3C 28-6
{
	ULONG64 all;
	struct
	{
		ULONG64 read_access : 1;
		ULONG64 write_access : 1;
		ULONG64 exec_access_supervisor : 1;
		ULONG64 memory_type : 3;
		ULONG64 ignore_pat_mem_type : 1;
		ULONG64 ignored1 : 1;
		ULONG64 accessed : 1;
		ULONG64 dirty : 1;
		ULONG64 exec_access_usermode : 1;
		ULONG64 ignored2 : 1;
		ULONG64 PhyPagePFN : 36;
		ULONG64 reserved : 4;                       //必须为0
		ULONG64 ignored3 : 11;
		ULONG64 suppress_ve : 1;
	}Bits;

}PTE, *PPTE;
static_assert(sizeof(PTE) == sizeof(ULONG64), "PTE Size ERROR");

//https://github.com/qq1045551070/VtToMe/blob/dd6b254ff51351dd7dad0d8ba433fac7a9c54e58/VtToMe/VtToMe/VtHeader.h
// See: VPID AND EPT CAPABILITIES (请看白皮书 Vol. 3D A-7, 【处理器虚拟化技术】(157页))
typedef union _EptVpidCapMsr
{
	ULONG64 all;
	struct {
		ULONG64 support_execute_only_pages : 1;                        //!< [0]    为1时, 允许 execeute-only
		ULONG64 reserved1 : 5;                                         //!< [1:5]  
		ULONG64 support_page_walk_length4 : 1;                         //!< [6]	支持4级页表
		ULONG64 reserved2 : 1;                                         //!< [7]	
		ULONG64 support_uncacheble_memory_type : 1;                    //!< [8]	EPT 允许使用 UC 类型(0),请参考【处理器虚拟化技术】(第4.4.1.3节)
		ULONG64 reserved3 : 5;                                         //!< [9:13] 
		ULONG64 support_write_back_memory_type : 1;                    //!< [14]	EPT 允许使用 WB 类型(6)
		ULONG64 reserved4 : 1;                                         //!< [15]
		ULONG64 support_pde_2mb_pages : 1;                             //!< [16]	EPT 支持2MB页面
		ULONG64 support_pdpte_1_gb_pages : 1;                          //!< [17]	EPT 支持1GB页面
		ULONG64 reserved5 : 2;                                         //!< [18:19]
		ULONG64 support_invept : 1;                                    //!< [20]	为1时, 支持 invept 指令
		ULONG64 support_accessed_and_dirty_flag : 1;                   //!< [21]	为1时, 支持 dirty 标志位
		ULONG64 reserved6 : 3;                                         //!< [22:24]
		ULONG64 support_single_context_invept : 1;                     //!< [25]	为1时, 支持 single-context invept
		ULONG64 support_all_context_invept : 1;                        //!< [26]	为1时, 支持 all-context invept
		ULONG64 reserved7 : 5;                                         //!< [27:31]
		ULONG64 support_invvpid : 1;                                   //!< [32]	为1时, 支持 invvpid 指令
		ULONG64 reserved8 : 7;                                         //!< [33:39]
		ULONG64 support_individual_address_invvpid : 1;                //!< [40]	为1时, 支持 individual-address invvpid 指令
		ULONG64 support_single_context_invvpid : 1;                    //!< [41]	为1时, 支持 single-context invvpid 指令
		ULONG64 support_all_context_invvpid : 1;                       //!< [42]	为1时, 支持 all-context invvpid 指令
		ULONG64 support_single_context_retaining_globals_invvpid : 1;  //!< [43]	为1时, 支持 single-context-retaining-globals invvpid
		ULONG64 reserved9 : 20;                                        //!< [44:63]
	}Bits;
}EptVpidCapMsr, * pEptVpidCapMsr;
static_assert(sizeof(EptVpidCapMsr) == sizeof(ULONG64), "Ia32VmxEptVpidCapMsr size error!");

// https://github.com/zhuhuibeishadiao/PFHook/blob/65b3d530d3a773bc1e5e6b53f0007463b6d6a503/PFHook_sys/base/ept.h
typedef struct _EPT_QULIFICATION_TABLE {
	ULONG64 Read : 1;      //0读
	ULONG64 Write : 1;     //1写
	ULONG64 Execute : 1;  //2执行
	ULONG64 ReadAble : 1; //3为1时表表示GPA可读
	ULONG64 WriteAble : 1;   //4为1时表表示GPA可写
	ULONG64 ExecuteAble : 1;//5为1时表表示GPA可执行
	ULONG64 reserved : 1;//// 6保留
	ULONG64 Valid : 1;//为1时 7表明存在一个线性地址
	ULONG64 TranSlation : 1;////8为1时表面EPT VIOLATION发生在GPA转HPA 为0表明发生在对guest paging-stucture表现访问环节
	ULONG64 reserved2 : 1;//9保留 为0
	ULONG64 NMIunblocking : 1;//10为1表明执行啦IRET指令，并且NMI阻塞已经解除
	ULONG64 reserved3 : 1;//11
	ULONG64 reserved4 : 13;//23:11
	ULONG64 GET_PTE : 1;//24
	ULONG64 GET_PAGE_FRAME : 1;//25
	ULONG64 FIX_ACCESS : 1;//26为1时 进行access ringht修复工作
	ULONG64 FIX_MISCONF : 1;//27为1时 进行misconfiguration修复工作
	ULONG64 FIX_FIXING : 1;//28为1时 修复 为0映射
	ULONG64 EPT_FORCE : 1;//29为1时 强制进行映射
	ULONG64 reserved5 : 1;
} EPT_QULIFICATION_TABLE, * P_EPT_QULIFICATION_TABLE;


typedef union _IA32_MTRR_DEF_TYPE_Reg
{
	ULONG64 all;
	struct
	{
		ULONG64 DefaultMemoryType : 3;
		ULONG64 Reserved1 : 7;
		ULONG64 FixedRangeMtrrEnable : 1;
		ULONG64 MtrrEnable : 1;
		ULONG64 Reserved2 : 52;
	}Bits;


}IA32_MTRR_DEF_TYPE_Reg, * PIA32_MTRR_DEF_TYPE_Reg;


typedef union _IA32_MTRR_CAPABILITIES_REGISTER
{
	struct
	{
		ULONG64 VariableRangeCount : 8;
		ULONG64 FixedRangeSupported : 1;
		ULONG64 Reserved1 : 1;
		ULONG64 WcSupported : 1;
		ULONG64 SmrrSupported : 1;
		ULONG64 Reserved2 : 52;
	}Bits;

	ULONG64 all;
} IA32_MTRR_CAPABILITIES_REGISTER, * PIA32_MTRR_CAPABILITIES_REGISTER;

typedef union _IA32_MTRR_PHYSBASE_REGISTER
{
	struct
	{

		ULONG64 Type : 8;
		ULONG64 Reserved1 : 4;
		ULONG64 PhysBase : 36;
		ULONG64 Reserved2 : 16;
	}Bits;

	ULONG64 all;
} IA32_MTRR_PHYSBASE_REGISTER, * PIA32_MTRR_PHYSBASE_REGISTER;

typedef union _IA32_MTRR_PHYSMASK_REGISTER
{
	struct
	{
		ULONG64 Type : 8;
		ULONG64 Reserved1 : 3;
		ULONG64 Valid : 1;
		ULONG64 PhysMask : 36;
		ULONG64 Reserved2 : 16;
	}Bits;
	ULONG64 all;
} IA32_MTRR_PHYSMASK_REGISTER, * PIA32_MTRR_PHYSMASK_REGISTER;

typedef struct _MTRR_RANGE_DESCRIPTOR
{
	SIZE_T PhysBaseAddress;
	SIZE_T PhysEndAddress;
	UCHAR MemoryType;
	UINT32 enable;
} MTRR_RANGE_DESCRIPTOR, * PMTRR_RANGE_DESCRIPTOR;


typedef PML4E EPT_PML4_POINTER, * PEPT_PML4_POINTER;
typedef PDPTE EPT_PML3_POINTER, * PEPT_PML3_POINTER;
typedef PDE_2MB EPT_PML2_M_ENTRY, * PEPT_PML2_ENTRY;
typedef PDE EPT_PML2_ENTRY, * PEPT_PML2_POINTER;
typedef PTE EPT_PML1_ENTRY, * PEPT_PML1_ENTRY;

typedef struct _VMM_EPT_PAGE_TABLE
{
	/**
	 * 28.2.2 Describes 512 contiguous 512GB memory regions each with 512 1GB regions.
	 */
	DECLSPEC_ALIGN(PAGE_SIZE) PML4E PML4[VMM_EPT_PML4E_COUNT];

	/**
	 * Describes exactly 512 contiguous 1GB memory regions within a our singular 512GB PML4 region.
	 */
	DECLSPEC_ALIGN(PAGE_SIZE) PDPTE PML3[VMM_EPT_PML3E_COUNT];

	/**
	 * For each 1GB PML3 entry, create 512 2MB entries to map identity.
	 * NOTE: We are using 2MB pages as the smallest paging size in our map, so we do not manage individiual 4096 byte pages.
	 * Therefore, we do not allocate any PML1 (4096 byte) paging structures.
	 */
	DECLSPEC_ALIGN(PAGE_SIZE) PDE_2MB PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];

	LIST_ENTRY DynamicSplitList;


} VMM_EPT_PAGE_TABLE, * PVMM_EPT_PAGE_TABLE;

typedef struct _VMM_EPT_DYNAMIC_SPLIT
{
	/*
	 * The 4096 byte page table entries that correspond to the split 2MB table entry.
	 */
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML1_ENTRY PML1[VMM_EPT_PML1E_COUNT];

	/*
	 * The pointer to the 2MB entry in the page table which this split is servicing.
	 */
	union
	{
		PEPT_PML2_ENTRY Entry;
		PEPT_PML2_POINTER Pointer;
	};

	/*
	 * Linked list entries for each dynamic split
	 */
	LIST_ENTRY DynamicSplitList;

} VMM_EPT_DYNAMIC_SPLIT, * PVMM_EPT_DYNAMIC_SPLIT;


typedef struct _EPT_STATE
{
	MTRR_RANGE_DESCRIPTOR MemoryRanges[9];							// Physical memory ranges described by the BIOS in the MTRRs. Used to build the EPT identity mapping.
	ULONG NumberOfEnabledMemoryRanges;								// Number of memory ranges specified in MemoryRanges
	EPTPointer  EptPointer;										// Extended-Page-Table Pointer 
	PVMM_EPT_PAGE_TABLE EptPageTable;							    // Page table entries for EPT operation
	LIST_ENTRY FakePageList;
	LIST_ENTRY FakePagePoolList;
	LIST_ENTRY DynamicSplitPoolList;

} EPT_STATE, *PEPT_STATE;


typedef union _IA32_VMX_EPT_VPID_CAP_REGISTER
{
	struct
	{
		/**
		 * [Bit 0] When set to 1, the processor supports execute-only translations by EPT. This support allows software to
		 * configure EPT paging-structure entries in which bits 1:0 are clear (indicating that data accesses are not allowed) and
		 * bit 2 is set (indicating that instruction fetches are allowed).
		 */
		ULONG64 ExecuteOnlyPages : 1;
		ULONG64 Reserved1 : 5;

		/**
		 * [Bit 6] Indicates support for a page-walk length of 4.
		 */
		ULONG64 PageWalkLength4 : 1;
		ULONG64 Reserved2 : 1;

		/**
		 * [Bit 8] When set to 1, the logical processor allows software to configure the EPT paging-structure memory type to be
		 * uncacheable (UC).
		 *
		 * @see Vol3C[24.6.11(Extended-Page-Table Pointer (EPTP))]
		 */
		ULONG64 MemoryTypeUncacheable : 1;
		ULONG64 Reserved3 : 5;

		/**
		 * [Bit 14] When set to 1, the logical processor allows software to configure the EPT paging-structure memory type to be
		 * write-back (WB).
		 */
		ULONG64 MemoryTypeWriteBack : 1;
		ULONG64 Reserved4 : 1;

		/**
		 * [Bit 16] When set to 1, the logical processor allows software to configure a EPT PDE to map a 2-Mbyte page (by setting
		 * bit 7 in the EPT PDE).
		 */
		ULONG64 Pde2MbPages : 1;

		/**
		 * [Bit 17] When set to 1, the logical processor allows software to configure a EPT PDPTE to map a 1-Gbyte page (by setting
		 * bit 7 in the EPT PDPTE).
		 */
		ULONG64 Pdpte1GbPages : 1;
		ULONG64 Reserved5 : 2;

		/**
		 * [Bit 20] If bit 20 is read as 1, the INVEPT instruction is supported.
		 *
		 * @see Vol3C[30(VMX INSTRUCTION REFERENCE)]
		 * @see Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)]
		 */
		ULONG64 Invept : 1;

		/**
		 * [Bit 21] When set to 1, accessed and dirty flags for EPT are supported.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		ULONG64 EptAccessedAndDirtyFlags : 1;

		/**
		 * [Bit 22] When set to 1, the processor reports advanced VM-exit information for EPT violations. This reporting is done
		 * only if this bit is read as 1.
		 *
		 * @see Vol3C[27.2.1(Basic VM-Exit Information)]
		 */
		ULONG64 AdvancedVmexitEptViolationsInformation : 1;
		ULONG64 Reserved6 : 2;

		/**
		 * [Bit 25] When set to 1, the single-context INVEPT type is supported.
		 *
		 * @see Vol3C[30(VMX INSTRUCTION REFERENCE)]
		 * @see Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)]
		 */
		ULONG64 InveptSingleContext : 1;

		/**
		 * [Bit 26] When set to 1, the all-context INVEPT type is supported.
		 *
		 * @see Vol3C[30(VMX INSTRUCTION REFERENCE)]
		 * @see Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)]
		 */
		ULONG64 InveptAllContexts : 1;
		ULONG64 Reserved7 : 5;

		/**
		 * [Bit 32] When set to 1, the INVVPID instruction is supported.
		 */
		ULONG64 Invvpid : 1;
		ULONG64 Reserved8 : 7;

		/**
		 * [Bit 40] When set to 1, the individual-address INVVPID type is supported.
		 */
		ULONG64 InvvpidIndividualAddress : 1;

		/**
		 * [Bit 41] When set to 1, the single-context INVVPID type is supported.
		 */
		ULONG64 InvvpidSingleContext : 1;

		/**
		 * [Bit 42] When set to 1, the all-context INVVPID type is supported.
		 */
		ULONG64 InvvpidAllContexts : 1;

		/**
		 * [Bit 43] When set to 1, the single-context-retaining-globals INVVPID type is supported.
		 */
		ULONG64 InvvpidSingleContextRetainGlobals : 1;
		ULONG64 Reserved9 : 20;
	}Bits;

	ULONG64 all;
} IA32_EPT_VPID_CAP_BITS, *PIA32_EPT_VPID_CAP_BITS;

typedef struct  _VMM_EPT_DYNAMIC_SPLIT_POOL
{
	PVMM_EPT_DYNAMIC_SPLIT dynamicsplit;
	LIST_ENTRY POOL_LIST;
	BOOLEAN IsUsed;

}VMM_EPT_DYNAMIC_SPLIT_POOL, * PVMM_EPT_DYNAMIC_SPLIT_POOL;

typedef struct _EPT_FAKE_PAGE
{

	DECLSPEC_ALIGN(PAGE_SIZE) CHAR FakePageCode[PAGE_SIZE];
	LIST_ENTRY POOL_LIST;
	ULONG64 VirtualAddress;
	ULONG64 PhyAddr;
	ULONG64 PhyPFN;
	ULONG64 PhysicalBaseAddressOfFakePageContents;
	PPTE OriginalEntryAddress;
	PPTE OriginalEntryBak;
	PTE FakeEntryForRW;
	PTE FakeEntryForX;
	BOOLEAN IsHook;
	PCHAR HookBytes;
} EPT_FAKE_PAGE, * PEPT_FAKE_PAGE;

typedef struct _EPT_FAKE_PAGE_POOL
{
	PEPT_FAKE_PAGE eptfakepage;
	LIST_ENTRY POOL_LIST;
	BOOLEAN IsUsed;

}EPT_FAKE_PAGE_POOL, * PEPT_FAKE_PAGE_POOL;

PPML4E _pPML4E;
PPDPTE _pPDPTE;
PVMM_EPT_PAGE_TABLE PageTable;
PEPT_STATE pEptState;
KSPIN_LOCK GLock;
BOOLEAN EnbaleHook;

BOOLEAN SetEptpointer(PVMM_EPT_PAGE_TABLE);
BOOLEAN CVInitEPT();
BOOLEAN CVEptMemeoryInit();
BOOLEAN CVBuildMtrrMap();
VOID SetMemMtrrInfo(EPT_PML2_M_ENTRY, ULONG64);


PPDE_2MB EptGetPDE2MBENTRY(PVMM_EPT_PAGE_TABLE EptPageTable,ULONG64 phy);
PPTE EptGetPTEENTRY(PVMM_EPT_PAGE_TABLE EptPageTable, ULONG64 phy);
BOOLEAN EptSplit2Mto4K(PVMM_EPT_PAGE_TABLE EptPageTable, ULONG64 PhysicalAddress, ULONG CoreIndex);
BOOLEAN HandleEPTPageHook(P_EPT_QULIFICATION_TABLE PQ, ULONG64 phy);
PVMM_EPT_DYNAMIC_SPLIT MallocSplitPageFromPagePoolList();
PEPT_FAKE_PAGE MallocFakePageFromPagePoolList();
VOID InitlizePagePoolForHook(int count);
PEPT_FAKE_PAGE GetFakePage(ULONG64 phy);
VOID FreeEPT();
VOID FreeEPTHOOKPagePool();