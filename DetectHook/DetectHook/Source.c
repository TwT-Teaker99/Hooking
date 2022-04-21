//#pragma comment(lib, "legacy_stdio_definitions.lib")


#define _NO_CRT_STDIO_INLINE


#include "Header.h"


#define IO_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2049, METHOD_BUFFERED, FILE_ANY_ACCESS)


PMODULE_LIST g_pml;
NTOSKRNL g_ntoskrnl;

NTOSKRNL g_partmgr;


UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\DetectHook");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\DetectHookS");


WCHAR wListSSDT[1000] = { 0 };
WCHAR wListIRP[1000] = { 0 };

WCHAR* arrIMJFunc1[] = { L"IRP_MJ_CREATE",
L"IRP_MJ_CREATE_NAMED_PIPE",
L"IRP_MJ_CLOSE",
L"IRP_MJ_READ",
L"IRP_MJ_WRITE",
L"IRP_MJ_QUERY_INFORMATION",
L"IRP_MJ_SET_INFORMATION",
L"IRP_MJ_QUERY_EA",
L"IRP_MJ_SET_EA",
L"IRP_MJ_FLUSH_BUFFERS",
L"IRP_MJ_QUERY_VOLUME_INFORMATION",
L"IRP_MJ_SET_VOLUME_INFORMATION",
L"IRP_MJ_DIRECTORY_CONTROL",
L"IRP_MJ_FILE_SYSTEM_CONTROL",
L"IRP_MJ_DEVICE_CONTROL",
L"IRP_MJ_INTERNAL_DEVICE_CONTROL",
L"IRP_MJ_SHUTDOWN",
L"IRP_MJ_LOCK_CONTROL",
L"IRP_MJ_CLEANUP",
L"IRP_MJ_CREATE_MAILSLOT",
L"IRP_MJ_QUERY_SECURITY",
L"IRP_MJ_SET_SECURITY",
L"IRP_MJ_POWER",
L"IRP_MJ_SYSTEM_CONTROL",
L"IRP_MJ_DEVICE_CHANGE",
L"IRP_MJ_QUERY_QUOTA",
L"IRP_MJ_SET_QUOTA",
L"IRP_MJ_PNP"
};



PMODULE_LIST GetListOfModules(PNTSTATUS pns)
{
	ULONG ul_NeededSize;
	ULONG* pul_ModuleListAddress = NULL;
	NTSTATUS ntS;
	PMODULE_LIST pml = NULL;

	ZwQuerySystemInformation(SystemModuleInformation, &ul_NeededSize, 0, &ul_NeededSize);


	pul_ModuleListAddress = (ULONG*)ExAllocatePool(PagedPool, ul_NeededSize);// cap bo nho loai pagedpool cho pul_Modulelistaddress voi size = ul_neededsize (byte)

	//if (!pul_ModuleListAddress)

	ntS = ZwQuerySystemInformation(SystemModuleInformation, pul_ModuleListAddress, ul_NeededSize, 0);

	if (ntS != STATUS_SUCCESS)
	{
		ExFreePool((PVOID)pul_ModuleListAddress);
		if (pns != NULL)
		{
			*pns = ntS;
		}
		return NULL;
	}

	pml = (PMODULE_LIST)pul_ModuleListAddress;
	if (pns != NULL)
		*pns = ntS;

	return pml;

}

VOID GetDriverName(ULONG uAddress, PWCHAR wName)
{
	NTSTATUS ntStatus;
	UINT32 i = 0;
	PMODULE_LIST g_pml1;
	g_pml1 = GetListOfModules(&ntStatus);
	if (!g_pml1)
	{
		return STATUS_UNSUCCESSFUL;
	}
	NTOSKRNL g_temp;

	for (USHORT count = 0; count < g_pml1->d_Modules; count++)
	{

		g_temp.base = (DWORD)g_pml1->a_Modules[count].p_Base;
		g_temp.end = ((DWORD)g_pml1->a_Modules[count].p_Base + g_pml1->a_Modules[count].ul_Size);

		if (uAddress > g_temp.base && uAddress < g_temp.end)
		{
			strcpy(wName, (WCHAR*)(g_pml1->a_Modules[count].c_Path + g_pml1->a_Modules[count].us_NameOffset));
			i = 1;
			break;
		}



	}

	if (i == 0)
		wcscpy(wName, L"NoDriver");

	return;
}

VOID GetIMJFuncName(USHORT i, PWCHAR wName)
{

	KdPrint(("Detect: [%S], Func name la: [%S], length = %d", __FUNCTIONW__, arrIMJFunc1[i], wcslen(arrIMJFunc1[i])));

	for (int iTemp = 0; iTemp < wcslen(arrIMJFunc1[i]); iTemp++)
		wName[iTemp] = arrIMJFunc1[i][iTemp];

	//wName[wcslen(arrIMJFunc1[i])] = L"\0";
	//strcpy(wName, arrIMJFunc1[i]);

	return;
}


VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	IoDeleteDevice(pDriverObject->DeviceObject);
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);
	return;
}


void IdentifySSDTHooks(void)
{
	int i;
	for (i = 0; i < KeServiceDescriptorTable.NumberOfServices; i++)
	{
		if ((KeServiceDescriptorTable.ServiceTableBase[i] < g_ntoskrnl.base) || (KeServiceDescriptorTable.ServiceTableBase[i] > g_ntoskrnl.end))
		{

			KdPrint(("[Detect_SSDT_CMC] Fun %d is hooked at add %x\n", i, KeServiceDescriptorTable.ServiceTableBase[i]));
			WCHAR wTemp[200] = { 0 };
			WCHAR wNameDriver[50] = { 0 };
			WCHAR funName[250] = { 0 };
			GetDriverName(KeServiceDescriptorTable.ServiceTableBase[i], wNameDriver);
			KdPrint(("Detect: something.... %s", KeServiceDescriptorTable.ParamTableBase[i]));
			GetSSDTFunction(i, funName);
			swprintf(wTemp, L"\t - Function [%d][%S] is hooked at add [%x] by driver [%S] ", i, funName, KeServiceDescriptorTable.ServiceTableBase[i], wNameDriver);
			KdPrint(("Detect: wTemp = %S", wTemp));
			//memset(wListSSDT, 0, 1000);
			wcscat(wListSSDT, wTemp);
			wcscat(wListSSDT, L".\n");
		}
	}
}


void IdentifyIRPHooks(PWCHAR pDriverName)
{
	UNICODE_STRING u_dvPartmgr = RTL_CONSTANT_STRING(L"\\Device\\PartmgrControl");
	NTSTATUS ntStatus;

	PFILE_OBJECT pFile = NULL;
	PDEVICE_OBJECT pDevice = NULL;
	ntStatus = IoGetDeviceObjectPointer(&u_dvPartmgr, FILE_READ_DATA, &pFile, &pDevice);
	int i = 0;
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		if ((pDevice->DriverObject->MajorFunction[i] < g_partmgr.base) || (pDevice->DriverObject->MajorFunction[i] > g_partmgr.end))
		{
			WCHAR wTemp[100] = { 0 };
			WCHAR wTemp2[100] = { 0 };
			WCHAR wNameDriver[50] = { 0 };
			GetDriverName(pDevice->DriverObject->MajorFunction[i], wNameDriver);
			KdPrint(("[Detect_IRP_CMC] Func %S address %x in driver %S is hooked by %S ", arrIMJFunc1[i], pDevice->DriverObject->MajorFunction[i], pDriverName, wNameDriver));

			WCHAR wDataSend[500] = { 0 };
			WCHAR wIMJFun[50] = { 0 };
			GetIMJFuncName(i, wIMJFun);
			if (wcscmp(wNameDriver, L"NoDriver"))
			{
				swprintf(wTemp, L" is hooked at add [%x] by [%S]", pDevice->DriverObject->MajorFunction[i], wNameDriver);
				//	swprintf(wTemp2, L"Function %S in %S ", wIMJFun, pDriverName);

				//	wcscpy(wDataSend, wTemp2);
				//	wcscat(wDataSend, wTemp);

				wcscpy(wDataSend, L"\t- Function ");
				wcscat(wDataSend, wIMJFun);
				wcscat(wDataSend, L" in ");
				wcscat(wDataSend, pDriverName);
				wcscat(wDataSend, wTemp);

				//wcscat(wIMJFun, wTemp);
				//KdPrint(("Detect_IRP: datasend = %S", wDataSend));
				//memset(wListIRP, 0, 1000);
				wcscat(wListIRP, wDataSend);
				wcscat(wListIRP, L".\n");

			}
			//else
			//{
			//	GetDriverName(pDevice->DriverObject->MajorFunction[i], wNameDriver);
			//	swprintf(wTemp, L" is hooked at add [%x] by [%S]", pDevice->DriverObject->MajorFunction[i], wNameDriver);
			//		swprintf(wTemp2, L"Function %S in %S ", wIMJFun, pDriverName);

			//		wcscpy(wDataSend, wTemp2);
			//		wcscat(wDataSend, wTemp);

			//	wcscpy(wDataSend, L"\t- Function ");
			//	wcscat(wDataSend, wIMJFun);
			//	wcscat(wDataSend, L" in ");
			//	wcscat(wDataSend, pDriverName);
			//	wcscat(wDataSend, wTemp);

			//	wcscat(wIMJFun, wTemp);
			//	KdPrint(("Detect_IRP: datasend = %S", wDataSend));
			//	wcscat(wListIRP, wDataSend);
			//	wcscat(wListIRP, L".\n");
			//}


			//WCHAR wNameDriver[50] = { 0 };
			//GetDriverName(pDevice->DriverObject->MajorFunction[i], wNameDriver);
			//WCHAR wTemp[500] = { 0 };
			//wcscpy(wTemp, L"Function ");
			//wcscat(wTemp, arrIMJFunc1[i]);
			//wcscat(wTemp, L" in ");
			//wcscat(wTemp, pDriverName);
			//wcscat(wTemp, L" be hooked by ");
			//wcscat(wTemp, wNameDriver);
			//KdPrint(("Detect_IRP: wTemp = %S", wTemp));
			//wcscat(wListIRP, wTemp);
			//wcscat(wListIRP, L"; ");




		}
	}

}


NTSTATUS
DefaultFunc(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp)
{

	UNREFERENCED_PARAMETER(pDeviceObject); //tat canh bao cho pDeviceObject
	UNREFERENCED_PARAMETER(pIrp);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}


NTSTATUS DeviceIOControlFunc(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIRP)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	PIO_STACK_LOCATION stackLocation = NULL;
	WCHAR wMode[10] = { 0 };
	//PWCHAR pMode;
	ULONG uInputLength;
	stackLocation = IoGetCurrentIrpStackLocation(pIRP);

	uInputLength = stackLocation->Parameters.DeviceIoControl.InputBufferLength;

	KdPrint(("Detect: [%S] input length = %d\n", __FUNCTIONW__, uInputLength));

	if (stackLocation->Parameters.DeviceIoControl.IoControlCode == IO_BUFFER)
	{
		//pMode = pIRP->AssociatedIrp.SystemBuffer;
		KdPrint(("Detect: [%S] wMode = %S\n", __FUNCTIONW__, pIRP->AssociatedIrp.SystemBuffer));

	}

	ScanHook();

	KdPrint(("Detect: [%S] wListSSDT = %wZ\n", __FUNCTIONW__, wListSSDT));

	KdPrint(("Detect: [%S] wListIRP = %wZ\n", __FUNCTIONW__, wListIRP));

	if (!wcscmp(L"SSDT", pIRP->AssociatedIrp.SystemBuffer))
	{
		pIRP->IoStatus.Information = wcslen(wListSSDT) * 2;
		pIRP->IoStatus.Status = STATUS_SUCCESS;
		RtlCopyMemory(pIRP->AssociatedIrp.SystemBuffer, wListSSDT, wcslen(wListSSDT) * 2);
		IoCompleteRequest(pIRP, IO_NO_INCREMENT);
		
	}
	else
	{
		pIRP->IoStatus.Information = wcslen(wListIRP) * 2;
		pIRP->IoStatus.Status = STATUS_SUCCESS;
		RtlCopyMemory(pIRP->AssociatedIrp.SystemBuffer, wListIRP, wcslen(wListIRP) * 2);
		IoCompleteRequest(pIRP, IO_NO_INCREMENT);
		
	}
	wcscpy(wListSSDT, L" ");
	wcscpy(wListIRP, L" ");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS ntStatus;


	UNREFERENCED_PARAMETER(pRegistryPath);

	if (!pDriverObject)
	{
		KdPrint(("Detect: Tham so khong hop le"));
		return STATUS_INVALID_PARAMETER;
	}

	for (USHORT i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
		pDriverObject->MajorFunction[i] = DefaultFunc;


	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIOControlFunc;
	pDriverObject->DriverUnload = DriverUnload;

	ntStatus = IoCreateDevice(pDriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDriverObject->DeviceObject);
	if (!NT_SUCCESS(ntStatus))
		KdPrint(("Detect: Create device error"));
	else
		KdPrint(("Detect: Create device success"));

	ntStatus = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);

	if (!NT_SUCCESS(ntStatus))
		KdPrint(("CMC: Create symbolic link error"));
	else
		KdPrint(("CMC: Create symbolic link success"));
	
	return ntStatus;
}
PVOID ScanHook()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	int  count;
	g_ntoskrnl.base = 0;
	g_ntoskrnl.end = 0;
	g_pml = GetListOfModules(&ntStatus);
	if (!g_pml)
	{
		return STATUS_UNSUCCESSFUL;
	}
	for (count = 0; count < g_pml->d_Modules; count++)
	{
		DbgPrint("[Detect_CMC] module:  %s, add begin [%x] to [%x]", g_pml->a_Modules[count].c_Path + g_pml->a_Modules[count].us_NameOffset, (DWORD)g_pml->a_Modules[count].p_Base, (DWORD)g_pml->a_Modules[count].p_Base + g_pml->a_Modules[count].ul_Size);
		if (_stricmp("ntoskrnl.exe", g_pml->a_Modules[count].c_Path + g_pml->a_Modules[count].us_NameOffset) == 0)
		{
			g_ntoskrnl.base = (DWORD)g_pml->a_Modules[count].p_Base;
			g_ntoskrnl.end = ((DWORD)g_pml->a_Modules[count].p_Base + g_pml->a_Modules[count].ul_Size);
			IdentifySSDTHooks();
		}
		if (_stricmp("partmgr.sys", g_pml->a_Modules[count].c_Path + g_pml->a_Modules[count].us_NameOffset) == 0)
		{
			g_partmgr.base = (DWORD)g_pml->a_Modules[count].p_Base;
			g_partmgr.end = ((DWORD)g_pml->a_Modules[count].p_Base + g_pml->a_Modules[count].ul_Size);
			IdentifyIRPHooks(L"partmgr.sys");
		}
	}
	ExFreePool(g_pml);
	return;
}



