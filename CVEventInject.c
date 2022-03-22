#pragma once
#include "CVEventInject.h"


VOID InterruptEventInject(INTERRUPT_TYPE InterruptType, EXCEPTION_VECTORS Vector, BOOLEAN DeliverErrorCode, ULONG32 ErrorCode)
{
	INTERRUPT_INFO interrupt_info = { 0 };
	interrupt_info.Bits.Valid = TRUE;
	interrupt_info.Bits.InterruptType = InterruptType;
	interrupt_info.Bits.Vector = Vector;
	interrupt_info.Bits.DeliverCode = DeliverErrorCode;
	__vmx_vmwrite(VM_ENTRY_INTR_INFO, interrupt_info.all);
	if (DeliverErrorCode)
	{
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
	}
}
