#include "Header.h"

PVOID GetSSDTFunction(ULONG index, PWCHAR pszFunctionName)
{
	UNICODE_STRING ustrDllFileName;
	ULONG ulSSDTFunctionIndex = 0;;

	RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");

	GetSSDTFunctionIndex(ustrDllFileName, pszFunctionName, index);

	return NULL;
}

ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PWCHAR pszFunctionName, ULONG index)
{
	ULONG status = 0;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;

	NTSTATUS status1 = DllFileMap(ustrDllFileName, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status1))
	{
		KdPrint(("[Detect]DllFileMap Error!\n"));
		return status;
	}
	if (GetIndexFromExportTable(pBaseAddress, pszFunctionName, index) == 1) {
		status = 1;
	}

	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);
	return status;
}

NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE* phFile, HANDLE* phSection, PVOID* ppBaseAddress)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;
	InitializeObjectAttributes(&objectAttributes, &ustrDllFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenFile(&hFile, GENERIC_READ, &objectAttributes, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[Detect]ZwOpenFile Error! [error code: 0x%X]", status));
		return status;
	}
	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x1000000, hFile);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		KdPrint(("[Detect]ZwCreateSection Error! [error code: 0x%X]", status));
		return status;
	}
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		KdPrint(("[Detect]ZwMapViewOfSection Error! [error code: 0x%X]", status));
		return status;
	}

	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;

	return status;
}

ULONG GetIndexFromExportTable(PVOID pBaseAddress, PWCHAR pszFunctionName, ULONG index)
{
	ULONG result = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		KdPrint(("[Detect]DosError"));
		return 0;
	}
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		KdPrint(("[Detect]NtError"));
		return 0;
	}
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PULONG arrayOfFunctionAddresses = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions);
	PULONG arrayOfFunctionNames = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PULONG arrayOfFunctionOrdinals = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals);
	ULONG Base = pExportTable->Base;
	PCHAR lpName = NULL;
	ULONG functionOrdinal, functionAddress, position;
	for (ULONG i = 0; i < pExportTable->NumberOfNames; i++)
	{
		USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
		ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
		PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
		position = *((PULONG)((PUCHAR)lpFuncAddr + 1));
		if (index == position)
		{
			lpName = (PCHAR)((PUCHAR)pDosHeader + arrayOfFunctionNames[i]);
			strcpy(pszFunctionName, (PWCHAR)lpName);
			result = 1;
			break;
		}
	}
	return result;
}

BOOLEAN MDLWriteMemory(PVOID pBaseAddress, PVOID pWriteData, SIZE_T writeDataSize)
{
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
	}
	RtlCopyMemory(pNewAddress, pWriteData, writeDataSize);
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}