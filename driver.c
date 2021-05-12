#include <ntifs.h> 
#include <ntddk.h> 
#include <ntstrsafe.h> 
#include <stdlib.h>
#include "imports.h"
#include "operations.h"

NTSTATUS IOCTL(PDEVICE_OBJECT device_object, PIRP irp) {
	PUCHAR user_buffer;
	PIO_STACK_LOCATION io;

	__try {
		// microsoft naming convention is pIrpSp
		io = IoGetCurrentIrpStackLocation(irp);
		
		// check the length of the buffer
		// why: race condition between a dispatch and userland application exiting suddenly (user closes it, crashes, etc)
		// this will lead to PAGE_FAULT_IN_NONPAGED_AREA (0x50) when executing memcpy, the stack address content will look like
		// kd> db ffff8304d6d76000 
		// 	ffff8304`d6d76000  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??
		if (!io->Parameters.DeviceIoControl.InputBufferLength || io->Parameters.DeviceIoControl.InputBufferLength < 8) {
			DbgPrintEx(0, 0, "Length is %lu", io->Parameters.DeviceIoControl.InputBufferLength);
			goto StackFailure;
		}
		
		// copy the struct given by userland in the [in] buffer
		memcpy(&userland_operation, irp->AssociatedIrp.SystemBuffer, sizeof(userland_operation));
		
		// this is the userland [out] buffer
		user_buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

		switch (io->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_READ_MEM:
			__try {
				ReadProcessMemory((HANDLE)userland_operation.pid, userland_operation.address, (PVOID)user_buffer, userland_operation.size);
				break;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrintEx(0, 0, "[EXCEPTION]: IOCTL_READ_MEM");
				goto DefaultFailure;
			}
		case IOCTL_WRITE_MEM:
			__try {
				WriteProcessMemory((HANDLE)userland_operation.user_pid, (HANDLE)userland_operation.pid, (PVOID)userland_operation.write_buffer, (PVOID)userland_operation.address, userland_operation.size);
				break;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrintEx(0, 0, "[EXCEPTION]: IOCTL_WRITE_MEM");
				goto DefaultFailure;
			}
		case IOCTL_READ_MODBASE:
			__try {
				GetModuleList((HANDLE)userland_operation.pid, (PVOID)user_buffer, (LPWSTR)userland_operation.module_selection);
				break;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrintEx(0, 0, "[EXCEPTION]: IOCTL_READ_MODBASE");
				goto DefaultFailure;
			}
		case IOCTL_ALLOCATE_MEM:
			__try {
				AllocateVirtualMemory((HANDLE)userland_operation.pid, (ULONGLONG)userland_operation.address, (ULONG)userland_operation.protection_mode, (ULONG)userland_operation.allocation_type, userland_operation.size);
				break;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrintEx(0, 0, "[EXCEPTION]: IOCTL_ALLOCATE_MEM");
				goto DefaultFailure;
			}
		case IOCTL_PROTECT_MEM:
			__try {
				ProtectVirtualMemory((HANDLE)userland_operation.pid, (ULONGLONG)userland_operation.address, (ULONG)userland_operation.protection_mode, userland_operation.size);
				break;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrintEx(0, 0, "[EXCEPTION]: IOCTL_PROTECT_MEM");
				goto DefaultFailure;
			}
		default:
			goto DefaultFailure;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		goto DefaultFailure;
	}

	KeFlushIoBuffers(irp->MdlAddress, TRUE, FALSE);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

	DefaultFailure:
		KeFlushIoBuffers(irp->MdlAddress, TRUE, FALSE);
		irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	StackFailure:
		irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
}


void Unload(PDRIVER_OBJECT pDriverObject) {
	IoDeleteSymbolicLink(&SymbolicLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS Create(PDEVICE_OBJECT device_object, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Close(PDEVICE_OBJECT device_object, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	IoCreateDevice(driver_object, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
	IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
	IoSetDeviceInterfaceState(registry_path, TRUE);

	driver_object->MajorFunction[IRP_MJ_CREATE] = Create;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTL;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = Close;
	driver_object->DriverUnload = Unload;

	device_object->Flags |= DO_DIRECT_IO;
	device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}
