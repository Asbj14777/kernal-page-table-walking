#include <ntddk.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PTRS_PER_PTE 512
#define PTE_PRESENT 0x1
#define PTE_PS 0x80
#define PTE_PFN_MASK 0xFFFFFFFFFF000ULL

PHYSICAL_ADDRESS GetPhysicalAddress(PEPROCESS TargetProcess, PVOID VirtualAddress) {
    PHYSICAL_ADDRESS Invalid = { .QuadPart = -1LL };
    PHYSICAL_ADDRESS Cr3 = { .QuadPart = *(PULONG64)&TargetProcess->Pcb.DirectoryTableBase };  // Physical addr of PML4

    ULONG64 Va = (ULONG64)VirtualAddress;
    ULONG64 Indexes[4] = {
        (Va >> 39) & 0x1FF,  // PML4 index
        (Va >> 30) & 0x1FF,  // PDPT index
        (Va >> 21) & 0x1FF,  // PD index
        (Va >> 12) & 0x1FF   // PT index
    };

    PHYSICAL_ADDRESS CurrentPhys = Cr3;
    for (int Level = 0; Level < 4; Level++) {
        PVOID MappedDir = MmMapIoSpace(CurrentPhys, PAGE_SIZE, MmNonCached);
        if (!MappedDir) {
            return Invalid;
        }

        ULONG64* Pte = (ULONG64*)((ULONG64)MappedDir + Indexes[Level] * sizeof(ULONG64));
        ULONG64 PteValue = *Pte;

        MmUnmapIoSpace(MappedDir, PAGE_SIZE);

        if ((PteValue & PTE_PRESENT) == 0) {
            return Invalid;  // Not present
        }

        // Simplified: fail if large page (PS bit set) for levels < 3
        if (Level < 3 && (PteValue & PTE_PS) != 0) {
            return Invalid;  // Large page not handled
        }

        CurrentPhys.QuadPart = PteValue & PTE_PFN_MASK;
    }

    CurrentPhys.QuadPart += Va & (PAGE_SIZE - 1);  // Add byte offset
    return CurrentPhys;
}
NTSTATUS WriteViaPageTableWalking(PEPROCESS TargetProcess, PVOID TargetAddress, PVOID SourceBuffer, SIZE_T BufferSize) {
    PUCHAR Src = (PUCHAR)SourceBuffer;
    PUCHAR DstVa = (PUCHAR)TargetAddress;
    SIZE_T Remaining = BufferSize;

    while (Remaining > 0) {
        PHYSICAL_ADDRESS PhysAddr = GetPhysicalAddress(TargetProcess, DstVa);
        if (PhysAddr.QuadPart == -1LL) {
            return STATUS_ACCESS_VIOLATION;
        }

        // PhysAddr includes offset; get page base phys and offset
        ULONG64 Offset = (ULONG64)DstVa & (PAGE_SIZE - 1);
        PHYSICAL_ADDRESS PagePhys = { .QuadPart = PhysAddr.QuadPart - Offset };

        PVOID MappedPage = MmMapIoSpace(PagePhys, PAGE_SIZE, MmNonCached);
        if (!MappedPage) {
            return STATUS_UNSUCCESSFUL;
        }

        SIZE_T ToCopy = min(Remaining, PAGE_SIZE - Offset);
        RtlCopyMemory((PUCHAR)MappedPage + Offset, Src, ToCopy);

        MmUnmapIoSpace(MappedPage, PAGE_SIZE);

        Src += ToCopy;
        DstVa += ToCopy;
        Remaining -= ToCopy;
    }

    return STATUS_SUCCESS;
}
