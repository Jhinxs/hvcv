#include "SSDT.h"


ULONG64* GetSSDTBase()
{
	//ÔÝÊ±²»¿¼ÂÇKVAS
	ULONG64 lstar = __readmsr(0xC0000082);
	for (int i = 0; i < 1024; i++)
	{
		if (*(PUCHAR)(lstar + i) == 0x4c && *(PUCHAR)(lstar + i + 2) == 0x15)
		{
			if (*(PUCHAR)(lstar + i + 7) == 0x4c && *(PUCHAR)(lstar + i + 9) == 0x1d)
			{
				if (*(PUCHAR)(lstar + i + 14) == 0xf7 && *(PUCHAR)(lstar + i + 15) == 0x43)
				{
					ULONG64 KiSystemServiceRepeat = (ULONG64)(PUCHAR)lstar + i;
					ULONG offset = *(ULONG*)(KiSystemServiceRepeat + 3);
					ULONG64 SSDTBase = KiSystemServiceRepeat + offset + 7; //7= lea r10,[nt!KeServiceDescriptorTable]
					return SSDTBase;
				}

			}
		}
	}
	
	return NULL;

}
ULONG64 GetNTAPIAddress() 
{
	int SyscallNumber = 0x002c;     //NtOpenProcess = 0x0026;
	ULONG64* ssdt = GetSSDTBase();
	ULONG64 address = ((*(ULONG*)(*ssdt + SyscallNumber * 4)) >> 4) + *ssdt;
	return address;
}