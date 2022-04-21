#include "ntifs.h"
#include "ntstrsafe.h"

typedef NTSTATUS(*IRP_MJ_SERIES)
(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP pIrp
	);

DRIVER_DISPATCH FunDeviceControl;//+
#define IO_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2049, METHOD_BUFFERED, FILE_ANY_ACCESS)

WCHAR p_Notification[256];

//UNICODE_STRING S_Notification = {0};

IRP_MJ_SERIES g_OriFunc = NULL;

PDEVICE_OBJECT g_pDeviceObject = NULL;

NTSTATUS NTAPI ExRaiseHardError(IN NTSTATUS ErrorStatus, IN ULONG NumberOfParameters, IN ULONG UnicodeStringParameterMask,
	IN PULONG_PTR Parameters, IN ULONG ValidResponseOptions, OUT PULONG Response);


PIO_STACK_LOCATION p_StackLocation = NULL;

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


VOID
DriverUnload(
	PDRIVER_OBJECT pDriverObject)
{

	UNREFERENCED_PARAMETER(pDriverObject);

	KdPrint(("IRPH: Go cai dat [%s] [%S] !\n", __DATE__, __FUNCTIONW__));

	InterlockedExchange64((PLONG64)(&g_pDeviceObject->DriverObject->MajorFunction[IRP_MJ_WRITE]), (LONG64)g_OriFunc);// tra ve gia tri ban dau cua target
	//InterlockedExchange64((PLONG64)(&g_pDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]), (LONG64)g_DeviceIOFunc);

	ObDereferenceObject(g_pDeviceObject);
	return;
}


NTSTATUS
WriteFunc(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	WCHAR str_Svchost[] = L"\\Device\\HarddiskVolume1\\Windows\\System32\\svchost.exe";
	WCHAR str_Vds[] = L"\\Device\\HarddiskVolume1\\Windows\\System32\\vds.exe";
	//UNICODE_STRING pathAccept[2];
	//UNICODE_STRING text, title;
	//ULONG_PTR param[3];
	ULONG response;
	__try {
		PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);
		if (!IrpSp)
		{
			KdPrint(("IRPH: [%S] Tham so khong hop le:IrpSp!\n", __FUNCTIONW__));
			pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return pIrp->IoStatus.Status;
		}
		PEPROCESS pEProc = IoThreadToProcess(pIrp->Tail.Overlay.Thread);
		if (!pEProc)
		{
			KdPrint(("IRPH: [%S] tham so khong hop le:pEProc!\n", __FUNCTIONW__));
			pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return pIrp->IoStatus.Status;
		}
		HANDLE hProc = PsGetCurrentProcessId();
		PUNICODE_STRING puniProcImageName = { 0 };

		Status = SeLocateProcessImageName(pEProc, &puniProcImageName);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("IRPH: [%S] SeLocateProcessImageName khong thanh cong, ma loi:%X\n", __FUNCTIONW__, Status));
			pIrp->IoStatus.Status = Status;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return pIrp->IoStatus.Status;
		}

		UINT64 Sector = (UINT64)IrpSp->Parameters.Write.ByteOffset.QuadPart / 512;

		if (Sector < 1)
		{

			if (!wcscmp(puniProcImageName->Buffer, str_Svchost))
				return g_OriFunc(pDeviceObject, pIrp);
			if (!wcscmp(puniProcImageName->Buffer, str_Vds))
				return g_OriFunc(pDeviceObject, pIrp);
			KdPrint(("IRPHWRITE: break 0 "));

			KdPrint(("IRPHWRITE: %wZ (PID = %I64u) dang co gang ghi vao mbr\n", puniProcImageName, (UINT64)hProc));


			WCHAR* w_Res;
			w_Res = wcscpy(p_Notification, puniProcImageName->Buffer);

			pIrp->IoStatus.Status = STATUS_ACCESS_DENIED;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return pIrp->IoStatus.Status;
		}

		return g_OriFunc(pDeviceObject, pIrp);
	}
	__except (1)
	{
		KdPrint(("IRPHWRITE: [%S] loi khong xac dinh, ma loi:%X\n", __FUNCTIONW__, GetExceptionCode()));
	}
	pIrp->IoStatus.Status = STATUS_ACCESS_DENIED;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;

	//return Status;
}

#ifdef __cplusplus
EXTERN_C
#endif
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath)
{

	UNREFERENCED_PARAMETER(pRegistryPath);

	KdPrint(("IRPH: driver duoc tai [%s] [%S]!\n", __DATE__, __FUNCTIONW__));

	if (!pDriverObject)
	{
		KdPrint(("IRPH: [%S] tham so khong hop le:pDriverObject!\n", __FUNCTIONW__));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_SUCCESS;

	for (USHORT i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)    // chi dinh default dispatch cho cac doi tuong IRP_MJ_Funcion
		pDriverObject->MajorFunction[i] = DefaultFunc;

	pDriverObject->DriverUnload = DriverUnload;

	// chen WriteFunc chan mbr
	UNICODE_STRING uniDriveName = RTL_CONSTANT_STRING(L"\\Device\\Harddisk0\\DR0");// ten doi tuong se duoc con tro tro den
	PFILE_OBJECT pFileObject = NULL;

	Status = IoGetDeviceObjectPointer(&uniDriveName, OBJ_OPENIF, &pFileObject, &g_pDeviceObject);// out pFileObject tro den doi tuong tep dai dien cho doi tuong thiet bi tuong ung, g_pDeviceObject tro den doi tuong thiet bi dai dien cho thiet bi logic, ao hoac vat ly duoc dat ten
	if (NT_SUCCESS(Status))
	{

		g_OriFunc = (IRP_MJ_SERIES)InterlockedExchange64((PLONG64)(&g_pDeviceObject->DriverObject->MajorFunction[IRP_MJ_WRITE]), (LONG64)WriteFunc);// gan ham IRP_MJ_WRite cu vao g_OriFun sau do gan IRP_MJ_WRITE bang ham WriteFunc
	//	g_DeviceIOFunc = (IRP_MJ_SERIES)InterlockedExchange64((PLONG64)(&g_pDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]), (LONG64)FuncDeviceControl);
		//KdPrint(("IRPH: [%S] add WriteFunc [%I64x], add g_oriFunc [%I64x]", __FUNCTIONW__, (LONG64)WriteFunc, (LONG64)g_OriFunc));

		ObDereferenceObject(pFileObject);// giai phong doi tuong 

		KdPrint(("IRPH: [%S] cai dat thanh cong!\n", __FUNCTIONW__));
	}
	else
		KdPrint(("IRPH: [%S] cai dat that bai, ma loi:%X\n", __FUNCTIONW__, Status));




	return Status;
}