#pragma once
#include "common.h"
#include "CVvmexitEntry.h"

VOID InterruptEventInject(INTERRUPT_TYPE InterruptType, EXCEPTION_VECTORS Vector, BOOLEAN DeliverErrorCode, ULONG32 ErrorCode);