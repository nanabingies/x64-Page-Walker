#include <ntdef.h>
#include <ntifs.h>
#include <intrin.h>
#include <ntddk.h>
#pragma warning(disable : 6328)
#pragma warning(disable : 4201)

UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"\\Device\\PageTable");
UNICODE_STRING DosDriverName = RTL_CONSTANT_STRING(L"\\DosDevices\\PageTable");

typedef unsigned short WORD;
PDEVICE_OBJECT pDeviceObject;

uintptr_t Getntoskrnlbase()
{
	typedef unsigned char uint8_t;
	uintptr_t Idt_base = (uintptr_t)KeGetPcr()->IdtBase;
	uintptr_t align_page = *(uintptr_t*)(Idt_base + 4) >> 0xc << 0xc;

	for (; align_page; align_page -= PAGE_SIZE)
	{
		for (int index = 0; index < PAGE_SIZE - 0x7; index++)
		{
			uintptr_t current_address = (intptr_t)(align_page) + index;

			if (*(uint8_t*)(current_address) == 0x48
				&& *(uint8_t*)(current_address + 1) == 0x8D
				&& *(uint8_t*)(current_address + 2) == 0x1D
				&& *(uint8_t*)(current_address + 6) == 0xFF) //48 8d 1D ?? ?? ?? FF
			{
				uintptr_t nto_base_offset = *(int*)(current_address + 3);
				uintptr_t nto_base_ = (current_address + nto_base_offset + 7);
				if (!(nto_base_ & 0xfff)) {
					return nto_base_;
				}
			}
		}
	}

	return 0x0;
}

NTSTATUS IoctlDefault(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IofCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS PageWalker() {
	unsigned __int64 Cr3 = 0;
	PEPROCESS SystemProcess = NULL;
	NTSTATUS rtstatus = STATUS_UNSUCCESSFUL;
	uintptr_t DirectoryTableBase = 0;
	unsigned int pml4Offset, pdpeOffset, pdeOffset, ptOffset, ppOffset;
	DWORD64 pml4, pdpe, pde, pt, physpage;
	MM_COPY_ADDRESS Address = { 0 };
	DWORD64 sentbytes;
	uintptr_t ntBase = 0x0;

	ntBase = Getntoskrnlbase();
	DbgPrint("[+] ntoskrnl base address : 0x%llX\n", ntBase);

	Cr3 = __readcr3();
	DbgPrint("[+] CR3 : %X\n", Cr3);

	rtstatus = PsLookupProcessByProcessId((HANDLE)0x4, &SystemProcess);
	if (!NT_SUCCESS(rtstatus)) {
		DbgPrint("[-] PsLookupProcessByProcessId Failed.\n");
		return STATUS_UNSUCCESSFUL;
	}
	
	
	DirectoryTableBase = *(uintptr_t*)((ULONG_PTR)SystemProcess + (ULONG)0x28);
	DbgPrint("[+] System EPROCESS : 0x%llX\n", (DWORD64)SystemProcess);
	DbgPrint("[+] DirectoryTableBase : %X\n", DirectoryTableBase);
	
	DbgPrint("\n[*] Walking ntoskrnl.exe Page Entries.\n\n");

	DWORD64 virtual_address = (DWORD64)ntBase;
	pml4Offset = (virtual_address >> 39) & 0x1FF;
	DbgPrint("[+] PhysAddr1 : %llX\n", (DWORD64)(DirectoryTableBase + (uintptr_t)pml4Offset * 8));
	DbgPrint("[+] PhysAddr2 : %llX\n", (DWORD64)((DirectoryTableBase + (uintptr_t)pml4Offset * 8) & 0xfffffffffffffff0));
	Address.PhysicalAddress.QuadPart = (DirectoryTableBase + ((uintptr_t)pml4Offset) * 8) & 0xfffffffffffffff0;
	
	// Supported only on Windows 10
	MmCopyMemory(&pml4, Address, sizeof(DWORD64), MM_COPY_MEMORY_PHYSICAL, &sentbytes);
	
	DbgPrint("[+] pml4Offset : %X\n", pml4Offset);
	DbgPrint("[+] pml4 : 0x%llX\n", pml4);
	
	pdpeOffset = (virtual_address >> 30) & 0x1ff;
	Address.PhysicalAddress.QuadPart = (pml4 & 0xFFFFFFFFFF000) + (pdpeOffset * 8);
	MmCopyMemory(&pdpe, Address, sizeof(DWORD64), MM_COPY_MEMORY_PHYSICAL, &sentbytes);

	DbgPrint("[+] pdpeOffset : %X\n", pdpeOffset);
	DbgPrint("[+] pdpe : 0x%llX\n", pdpe);

	pdeOffset = (virtual_address >> 21) & 0x1ff;
	Address.PhysicalAddress.QuadPart = (pdpe & 0xFFFFFFFFFF000) + (pdeOffset * 8);
	MmCopyMemory(&pde, Address, sizeof(DWORD64), MM_COPY_MEMORY_PHYSICAL, &sentbytes);

	DbgPrint("[+] pdeOffset : %X\n", pdeOffset);
	DbgPrint("[+] pde : 0x%llX\n", pde);

	ptOffset = (virtual_address >> 12) & 0x1FF;
	Address.PhysicalAddress.QuadPart = (pde & 0xFFFFFFFFFF000) + (ptOffset * 8);
	MmCopyMemory(&pt, Address, sizeof(DWORD64), MM_COPY_MEMORY_PHYSICAL, &sentbytes);

	if (pt == 0x0) {
		// Large Page bit set

		//Address.PhysicalAddress.QuadPart = ((pde & 0xFFFFFFFE00000) + (virtual_address & 0x1FFFFF));
		//MmCopyMemory(&physpage, Address, sizeof(DWORD64), MM_COPY_MEMORY_PHYSICAL, &sentbytes);
		physpage = ((pde & 0xFFFFFFFE00000) + (virtual_address & 0x1FFFFF));
		goto exit;
	}
	
	DbgPrint("[+] ptOffset : %X\n", ptOffset);
	DbgPrint("[+] pt : 0x%llX\n", pt);

	ppOffset = virtual_address & 0xFFF;
	physpage = (pt & 0xFFFFFFFFFF000) + ppOffset;
	//Address.PhysicalAddress.QuadPart = (pt & 0xFFFFFFFFFF000) + ppOffset;
	//MmCopyMemory(&physpage, Address, sizeof(DWORD64), MM_COPY_MEMORY_PHYSICAL, &sentbytes);

	DbgPrint("[+] ppOffset : %X\n", ppOffset);
	
exit:
	DbgPrint("[+] Physical Page : 0x%llX\n", physpage);

	/* For verification purposes */
	PHYSICAL_ADDRESS physicalAddress = { 0 };
	physicalAddress = MmGetPhysicalAddress((PVOID)virtual_address);
	DbgPrint("[+] MmGetPhysicalAddress(%llX) : 0x%llX\n", virtual_address, physicalAddress.QuadPart);

	ObDereferenceObject(SystemProcess);

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	IoDeleteSymbolicLink(&DosDriverName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS rtstatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(rtstatus)) {
		DbgPrint("[-] IoCreateDevice Failed.\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	rtstatus = IoCreateSymbolicLink(&DosDriverName, &DriverName);
	if (!NT_SUCCESS(rtstatus)) {
		DbgPrint("[-] IoCreateSymbolicLink Failed.\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = IoctlDefault;
	}
	DriverObject->DriverUnload = DriverUnload;

	if (!NT_SUCCESS(PageWalker())) {
		DbgPrint("[-] Unknown Error Encounted\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}