#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

#pragma warning(disable : 26451)

EXTERN_C DRIVER_DISPATCH DefaultDispatch;
EXTERN_C DRIVER_UNLOAD DriverUnload;

uintptr_t Getntoskrnlbase() {
	typedef unsigned char uint8_t;
	uintptr_t Idt_base = (uintptr_t)KeGetPcr()->IdtBase;
	uintptr_t align_page = *(uintptr_t*)(Idt_base + 4) >> 0xc << 0xc;

	for (; align_page; align_page -= PAGE_SIZE)
	{
		for (int index = 0; index < PAGE_SIZE - 0x7; index++)
		{
			uintptr_t current_address = (intptr_t)(align_page)+index;

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

auto PageWalker() -> NTSTATUS {

	MM_COPY_ADDRESS _sourceAddress{};
	SIZE_T NumberOfBytesTransferred;
	NTSTATUS status;

	UNICODE_STRING usString{};
	RtlInitUnicodeString(&usString, L"PsInitialSystemProcess");
	auto _address = reinterpret_cast<unsigned long long>(MmGetSystemRoutineAddress(&usString));
	NT_ASSERT(_address != __nullptr);
	DbgPrint("[+] PsInitialSystemProcess: %llX\n", _address);

	unsigned long long physPage;

	auto _largeEnabled = [&](unsigned long long _entry) -> VOID {
		DbgPrint("[+] Large Page enabled\n");

		physPage = ((_entry & 0xFFFFFFFFFF000) + (_address & 0x1fffff));
		
		DbgPrint("[+] Physical Page: %llX\n", physPage);

	};

	auto _cr3 = __readcr3();
	DbgPrint("[+] cr3: %llX\n", _cr3);

	USHORT pml4i = (_address >> 39) & 0x1ff;
	unsigned long long _pml4e = 0;
	_sourceAddress.PhysicalAddress.QuadPart = ((_cr3) + (pml4i * 8) & 0xfffffffffffffff0);

	status = MmCopyMemory(&_pml4e, _sourceAddress, sizeof PVOID, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] MmCopyMemory failed with error code: %X\n", status);
		return status;
	}
	DbgPrint("[+] PML4i: %X\t PML4e: %llX\n", pml4i, _pml4e);
	
	USHORT _pdpti = (_address >> 30) & 0x1ff;
	unsigned long long _pdpte = 0;
	_sourceAddress.PhysicalAddress.QuadPart = ((_pml4e & 0xFFFFFFFFFF000) + (_pdpti * 8));
	
	status = MmCopyMemory(&_pdpte, _sourceAddress, sizeof PVOID, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] MmCopyMemory failed with error code: %X\n", status);
		return status;
	}
	DbgPrint("[+] PDPTi: %X\t PDPTe: %llX\n", _pdpti, _pdpte);

	auto _largePageCheck = (1 << 7) & (_pdpte);
	if (_largePageCheck > 0) {
		// large page bit is set
		_largeEnabled(_pdpte);
		goto _out;
	}

	USHORT _pdi = (_address >> 21) & 0x1ff;
	unsigned long long _pde = 0;
	_sourceAddress.PhysicalAddress.QuadPart = ((_pdpte & 0xFFFFFFFFFF000) + (_pdi * 8));

	status = MmCopyMemory(&_pde, _sourceAddress, sizeof PVOID, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] MmCopyMemory failed with error code: %X\n", status);
		return status;
	}
	DbgPrint("[+] PDi: %X\t PDe: %llX\n", _pdi, _pde);

	_largePageCheck = (1 << 7) & (_pde);
	if (_largePageCheck > 0) {
		// large page bit is set
		_largeEnabled(_pde);
		goto _out;
	}

	USHORT _pti = (_address >> 12) & 0x1ff;
	unsigned long long _pte = 0;
	_sourceAddress.PhysicalAddress.QuadPart = ((_pde & 0xFFFFFFFFFF000) + (_pti * 8));

	status = MmCopyMemory(&_pte, _sourceAddress, sizeof PVOID, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] MmCopyMemory failed with error code: %X\n", status);
		return status;
	}
	DbgPrint("[+] PTi: %X\t PTe: %llX\n", _pti, _pte);

	_largePageCheck = (1 << 7) & (_pde);
	if (_largePageCheck > 0) {
		// large page bit is set
		_largeEnabled(_pte);
		goto _out;
	}

	USHORT _physIndex = (_address & 0xfff);
	physPage = ((_pte & 0xFFFFFFFFFF000) + _physIndex);
	
	DbgPrint("[+] Physical Page: %llX\n", physPage);

_out:
	auto origPhysical = MmGetPhysicalAddress(reinterpret_cast<PVOID>(_address));
	DbgPrint("[+] Original Physical Address: %llX\n", origPhysical.QuadPart);

	return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING) {

	PageWalker();
	__debugbreak();

	return STATUS_SUCCESS;
}
