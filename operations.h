#pragma once
#include <ntifs.h> 
#include <ntddk.h>
#include <ntstrsafe.h> 
#include <stdlib.h>
#include "definitions.h"

BOOLEAN hasAttached;
NTSTATUS GetModuleList(HANDLE PID, PVOID user_buffer, LPWSTR module_selection) {
	KAPC_STATE APC;

	// Create a module list array, we do this because we can't use module_selection
	// for comparison while we're attached to the processes stack
	PMODULE_INFO ModuleList = ExAllocatePool(PagedPool, sizeof(MODULE_INFO) * 512);
	if (ModuleList == NULL)
		return STATUS_MEMORY_NOT_ALLOCATED;

	RtlZeroMemory(ModuleList, sizeof(MODULE_INFO) * 512);

	__try {
		PEPROCESS TargetProcess;
		PsLookupProcessByProcessId(PID, &TargetProcess);

		if (!TargetProcess) {
			return STATUS_ACCESS_DENIED;
		}

		PPEB Peb = PsGetProcessPeb(TargetProcess);

		if (!Peb)
			return STATUS_INVALID_PARAMETER;

		KeStackAttachProcess(TargetProcess, &APC);
		hasAttached = TRUE;

		UINT64 Ldr = (UINT64)Peb + PEBLDR_OFFSET;
		ProbeForRead((CONST PVOID)Ldr, 8, 8);

		PLIST_ENTRY ModListHead = (PLIST_ENTRY)(*(PULONG64)Ldr + PEBLDR_MEMORYLOADED_OFFSET);
		ProbeForRead((CONST PVOID)ModListHead, 8, 8);

		PLIST_ENTRY Module = ModListHead->Flink;

		// Build an array of ModuleList structs
		DWORD index = 0;
		while (ModListHead != Module) {
			LDR_DATA_TABLE_ENTRY* Module_Ldr = (LDR_DATA_TABLE_ENTRY*)(Module);


			ModuleList[index].Base = Module_Ldr->DllBase;
			ModuleList[index].Size = Module_Ldr->SizeOfImage;
			RtlCopyMemory(ModuleList[index].Name, Module_Ldr->BaseDllName.Buffer, Module_Ldr->BaseDllName.Length);

			Module = Module->Flink;
			index++;
		}

		KeUnstackDetachProcess(&APC);
		hasAttached = FALSE;

		// Once out of the process stack, process the array
		for (DWORD i = 0; i < 512; i++) {
			MODULE_INFO CurrentModule = ModuleList[i];
			// compare userland string with module string
			if (_wcsicmp(CurrentModule.Name, module_selection) == 0) {
				// return userland the baseaddress
				RtlCopyMemory(user_buffer, &CurrentModule.Base, sizeof(ULONGLONG));
				break;
			}
		}

		ObDereferenceObject(TargetProcess);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// Check to see if we've attached or not to avoid APC bsod
		if (hasAttached) {
			KeUnstackDetachProcess(&APC);
			hasAttached = FALSE;
		}
		return STATUS_ACCESS_DENIED;
	}
}


NTSTATUS ProtectVirtualMemory(HANDLE PID, ULONGLONG address, ULONG protection_mode, SIZE_T size) {
	KAPC_STATE apc;
	SIZE_T result;
	ULONG old_protection;
	PEPROCESS target_process;

	if (!(address != 0 && address > 0 && address < 0x7FFFFFFFFFFF)) {
		return STATUS_ACCESS_DENIED;
	}

	__try {
		PsLookupProcessByProcessId(PID, &target_process);
		KeStackAttachProcess(target_process, &apc);
		result = ZwProtectVirtualMemory(ZwCurrentProcess(), (PVOID)&address, &size, protection_mode, &old_protection);
		KeUnstackDetachProcess(&apc);
		ObfDereferenceObject(target_process);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS AllocateVirtualMemory(HANDLE pid, ULONGLONG address, ULONG protection_mode, ULONG allocation_type, SIZE_T size) {
	KAPC_STATE apc;
	SIZE_T result;
	PEPROCESS target_process;

	if (!(address != 0 && address > 0 && address < 0x7FFFFFFFFFFF)) {
		return STATUS_ACCESS_DENIED;
	}
	__try {
		PsLookupProcessByProcessId(pid, &target_process);
		KeStackAttachProcess(target_process, &apc);
		result = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID)&address, 0, &size, allocation_type, protection_mode);
		KeUnstackDetachProcess(&apc);
		ObfDereferenceObject(target_process);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS ReadProcessMemory(HANDLE pid, PVOID source_address, PVOID target_address, SIZE_T size) {
	SIZE_T result;
	PEPROCESS SourceProcess, TargetProcess;

	if (!((ULONGLONG)source_address != 0 && (ULONGLONG)source_address > 0 && (ULONGLONG)source_address < 0x7FFFFFFFFFFF)) {
		return STATUS_ACCESS_DENIED;
	}

	__try {
		PsLookupProcessByProcessId(pid, &SourceProcess);
		if (!SourceProcess) {
			return STATUS_ACCESS_DENIED;
		}
		TargetProcess = PsGetCurrentProcess();
		MmCopyVirtualMemory(SourceProcess, source_address, TargetProcess, target_address, size, KernelMode, &result);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS WriteProcessMemory(HANDLE user_pid, HANDLE target_pid, PVOID user_address, PVOID target_address, SIZE_T size) {
	SIZE_T result;
	PEPROCESS user_process, target_process;

	if (!((ULONGLONG)user_address != 0 && (ULONGLONG)user_address > 0 && (ULONGLONG)user_address < 0x7FFFFFFFFFFF)) {
		return STATUS_ACCESS_DENIED;
	}
	if (!((ULONGLONG)target_address != 0 && (ULONGLONG)target_address > 0 && (ULONGLONG)target_address < 0x7FFFFFFFFFFF)) {
		return STATUS_ACCESS_DENIED;
	}

	__try {
		PsLookupProcessByProcessId(user_pid, &user_process);
		PsLookupProcessByProcessId(target_pid, &target_process);
		if (!target_process || !user_process) {
			return STATUS_ACCESS_DENIED;
		}
		if (!((ULONGLONG)user_address != 0 && (ULONGLONG)user_address > 0 && (ULONGLONG)user_address < 0x7FFFFFFFFFFF)) {
			return STATUS_ACCESS_DENIED;
		}
		if (!((ULONGLONG)target_address != 0 && (ULONGLONG)target_address > 0 && (ULONGLONG)target_address < 0x7FFFFFFFFFFF)) {
			return STATUS_ACCESS_DENIED;
		}

		MmCopyVirtualMemory(user_process, user_address, target_process, target_address, size, KernelMode, &result);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}
