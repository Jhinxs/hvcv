//https://github.com/haidragon/newbluepill    ��Ҫ���ڶ�̬������������
#include "selector.h"

NTSTATUS InitializeSegmentSelector(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, ULONG64 GdtBase)
{
	PSEGMENT_DESCRIPTOR2 SegDesc;

	if (!SegmentSelector)
	{
		return STATUS_INVALID_PARAMETER;
	}

	//
	// �����ѡ���ӵ�T1 = 1��ʾ����LDT�е���, ����û��ʵ���������
	//
	if (Selector & 0x4)
	{

		return STATUS_INVALID_PARAMETER;
	}

	//
	// ��GDT��ȡ��ԭʼ�Ķ�������
	//
	SegDesc = (PSEGMENT_DESCRIPTOR2)((PUCHAR)GdtBase + (Selector & ~0x7));

	//
	// ��ѡ����
	//
	SegmentSelector->sel = Selector;

	//
	// �λ�ַ15-39λ 55-63λ
	//
	SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;

	//
	// ���޳�0-15λ  47-51λ, ������ȡ��
	//
	SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;

	//
	// ������39-47 51-55 ע��۲�ȡ��
	//
	SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;

	//
	// �����ж����Ե�DTλ, �ж��Ƿ���ϵͳ�����������Ǵ������ݶ�������
	//
	if (!(SegDesc->attr0 & LA_STANDARD))
	{
		ULONG64 tmp;

		//
		// �����ʾ��ϵͳ��������������������, �о�����Ϊ64λ׼���İ�,
		// 32λ����λ�ַֻ��32λ��. �ѵ�64λ������ʲô������?
		//
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));

		SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
	}

	//
	// ���Ƕν��޵�����λ, 1Ϊ4K. 0Ϊ1BYTE
	//
	if (SegmentSelector->attributes.fields.g)
	{
		//
		// �������λΪ1, ��ô�ͳ���4K. ���ƶ�12λ
		//
		SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
	}

	return STATUS_SUCCESS;
}




NTSTATUS FillGuestSelectorData(ULONG64 GdtBase, ULONG Segreg, USHORT
	Selector)
{

	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG uAccessRights;

	InitializeSegmentSelector(&SegmentSelector, Selector, GdtBase);
	uAccessRights = ((PUCHAR)&SegmentSelector.attributes)[0] + (((PUCHAR)&
		SegmentSelector.attributes)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	__vmx_vmwrite(VMCS_GUSTAREA_ES + Segreg * 2, Selector);
	__vmx_vmwrite(VMCS_GUSTAREA_ES_BASE + Segreg * 2, SegmentSelector.base);
	__vmx_vmwrite(VMCS_GUSTAREA_ES_LIMT + Segreg * 2, SegmentSelector.limit);
	__vmx_vmwrite(VMCS_GUSTAREA_ES_ACCR + Segreg * 2, uAccessRights);
	if ((Segreg == LDTR) || (Segreg == TR))
		// don't setup for FS/GS - their bases are stored in MSR values
		__vmx_vmwrite(VMCS_GUSTAREA_ES_BASE + Segreg * 2, SegmentSelector.base);
	return STATUS_SUCCESS;
}
