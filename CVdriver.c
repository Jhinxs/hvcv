#include "common.h"
#include "SSDT.h"

NTSTATUS DrvUnLoad(PDRIVER_OBJECT pDriver)
{
	CVStopVT();
	DbgPrintLog("[+] Driver Unload Success!\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pPath)
{

	pDriver->DriverUnload = DrvUnLoad;
	if (CVStartVT())
	{
		DbgPrintLog("[+] CV Simply VT Start Successfully\n");
	}
	else
	{
		DbgPrintLog("[!] CV Simply VT Start Error\n");
	}


	//GetNTAPIAddress();
	DbgPrintLog("[+] Driver load Success!\n");
	return STATUS_SUCCESS;
}