#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include <ntimage.h>


typedef struct _MODULE_INFO {
	ULONG ul_Reserved1;
	ULONG ul_Reserved2;
	PVOID p_Base;
	ULONG ul_Size;
	ULONG ul_Flags;
	USHORT us_Index;
	USHORT us_Rank;
	USHORT us_LoadCount;
	USHORT us_NameOffset;
	CHAR c_Path[256];

} MODULE_INFO, * PMODULE_INFO, ** PPMODULE_INFO;

typedef struct _MODULE_LIST
{
	int d_Modules;
	MODULE_INFO a_Modules[];

} MODULE_LIST, * PMODULE_LIST, ** PPMODULE_LIST;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	MODULE_INFO Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _NTOSKRNL {
	ULONG base;
	ULONG end;
} NTOSKRNL, * PNTOSKRNL;

typedef enum tagSYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;
//return pointer point to PMODULE_LIST

NTKERNELAPI
NTSTATUS
ZwQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int* ServiceTableBase;
	unsigned int* ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char* ParamTableBase;
} SDTEntry_t;
#pragma pack()

// Import KeServiceDescriptorTable from ntoskrnl.exe.
__declspec(dllimport) SDTEntry_t KeServiceDescriptorTable;
//
//typedef struct _IMJFunc {
//	USHORT i;
//	PWCHAR wNameFunc;
//} IMJFunc;



extern WCHAR* arrIMJFunc1[];

PVOID GetSSDTFunction(ULONG index, PWCHAR pszFunctionName);

ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PWCHAR pszFunctionName, ULONG index);

NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE* phFile, HANDLE* phSection, PVOID* ppBaseAddress);

ULONG GetIndexFromExportTable(PVOID pBaseAddress, PWCHAR pszFunctionName, ULONG index);

PVOID ScanHook();