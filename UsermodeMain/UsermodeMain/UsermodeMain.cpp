
#include <iostream>
#include <Windows.h>

#define IO_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2049, METHOD_BUFFERED, FILE_ANY_ACCESS)

void GetFolderPath(char* pathFile, char* pathFolder)
{
	int i = 0;

	for (i = strlen(pathFile); i > 0; i--)
		if (pathFile[i] == '\\') {
			break;
		}
	lstrcpynA(pathFolder, pathFile, i + 2);
	return;

}

BOOL GetFunctionNameByIndex(DWORD ulModuleBase, int* Index, CHAR* lpszFunctionName)
{
	HANDLE hNtSection;
	PIMAGE_DOS_HEADER ulNtDllModuleBase;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS NtDllHeader;

	IMAGE_OPTIONAL_HEADER opthdr;
	DWORD* arrayOfFunctionAddresses;
	DWORD* arrayOfFunctionNames;
	WORD* arrayOfFunctionOrdinals;
	DWORD functionOrdinal;
	DWORD Base, x, functionAddress, position;
	char* functionName;
	IMAGE_EXPORT_DIRECTORY* pExportTable;
	BOOL bRetOK = FALSE;
	BOOL bInit = FALSE;

	ulNtDllModuleBase = (PIMAGE_DOS_HEADER)ulModuleBase;
	pDosHeader = (PIMAGE_DOS_HEADER)ulNtDllModuleBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return bRetOK;
	}
	NtDllHeader = (PIMAGE_NT_HEADERS)(ULONG)((ULONG)pDosHeader + pDosHeader->e_lfanew);
	if (NtDllHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return bRetOK;
	}
	opthdr = NtDllHeader->OptionalHeader;
	pExportTable = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ulNtDllModuleBase + opthdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	arrayOfFunctionAddresses = (DWORD*)((BYTE*)ulNtDllModuleBase + pExportTable->AddressOfFunctions);
	arrayOfFunctionNames = (DWORD*)((BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNames);
	arrayOfFunctionOrdinals = (WORD*)((BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNameOrdinals);

	Base = pExportTable->Base;

	for (x = 0; x < pExportTable->NumberOfFunctions; x++)
	{
		functionName = (char*)((BYTE*)ulNtDllModuleBase + arrayOfFunctionNames[x + Base - 1]);
		functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1;
		functionAddress = (DWORD)((BYTE*)ulNtDllModuleBase + arrayOfFunctionAddresses[functionOrdinal]);
		position = *((WORD*)(functionAddress + 1));

		if (*Index == position)
		{
			strcat(lpszFunctionName, functionName);
			bRetOK = TRUE;
			break;
		}
	}
	return bRetOK;
}


int main()
{
	std::cout << "Hello World!\n\n\n";
	int iChoose = 3;

	char path[256];
	char folderPath[256];
	char command[256];

	GetModuleFileNameA(NULL, path, 256);

	GetFolderPath(path, folderPath);

	strcat_s(folderPath, "DetectHook.sys");
	


	sprintf_s(command, "sc create DetectHook binPath= %s type= kernel", folderPath);

	system(command);

	system("sc start DetectHook");



	system("cls");

	while (iChoose)
	{

		std::cout << "Check hook kernel!!\n\n";
		std::cout << "Press 1 to check SSDT hook \n";
		std::cout << "Press 2 to check IRP hook \n";
		std::cout << "Press 0 to exit program \n\n";


		WCHAR wChoice[10] = { 0 };
		WCHAR wOutBuff[500] = { 0 };

		HANDLE device;
		BOOL status = FALSE;
		DWORD bytesReturned;
	
		std::cin >> iChoose;
		if (iChoose == 0)
		{
			break;
		}
		else if ( iChoose == 1 || iChoose == 2)
		{
			if (iChoose == 1)
			{
				wcscpy_s(wChoice, L"SSDT");
			}
			else
				wcscpy_s(wChoice, L"IRP");

			device = CreateFileW(L"\\\\.\\DetectHookS", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);


			if (device == INVALID_HANDLE_VALUE)
			{
				std::cout << "Can not open device, err = " << GetLastError() << std::endl;
				system("pause");
				system("sc stop DetectHook");
				system("sc delete DetectHook");
				return FALSE;
			}


			status = DeviceIoControl(device, IO_BUFFER, wChoice, sizeof(wChoice), wOutBuff, sizeof(wOutBuff), &bytesReturned, (LPOVERLAPPED)NULL);


			std::wcout << L"\nResult is:\n\n" << wOutBuff << std::endl;

			//system("pause");
			//system("close.bat");
			//std::cout << "Da go bo driver \n";
			//std::cout << "Nhan enter de tiep tuc \n";
			system("pause");
			system("cls");

		}
		else
		{
			std::cout << "Input Error !!  ";
			system("pause");
			system("cls");
		}

		
	}

	system("sc stop DetectHook");
	system("sc delete DetectHook");

	return 0;


}

