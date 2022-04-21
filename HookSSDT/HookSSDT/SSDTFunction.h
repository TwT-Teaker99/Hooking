#include <ntddk.h>
#include <ntimage.h>


#pragma pack(1)
typedef struct _SERVICE_DESCIPTOR_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfService;
	PUCHAR ParamTableBase;
}SSDTEntry, *PSSDTEntry;
#pragma pack()

extern SSDTEntry __declspec(dllimport) KeServiceDescriptorTable;

PVOID GetSSDTFunction(PCHAR pszFunctionName);

ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName);

NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE *phFile, HANDLE *phSection, PVOID *ppBaseAddress);

ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName);
