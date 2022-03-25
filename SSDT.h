#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

ULONG64* GetSSDTBase();
ULONG64 GetNTAPIAddress();