#pragma once 
#include <ntifs.h>

EXTERN_C _IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ VOID KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);
EXTERN_C _IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ ULONG KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);

EXTERN_C _IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ VOID KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);