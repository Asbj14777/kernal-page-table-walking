#include <ntddk.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PTE_PRESENT 0x1
#define PTE_PS      0x80
#define PTE_PFN_MASK 0xFFFFFFFFFF000ULL

// Retrieve the DirectoryTableBase (CR3) for a given process
ULONG64 GetProcessCR3(PEPROCESS Process) {
    // Offset 0x288 is typical on Windows 11; confirm for your build
    ULONG64* DirBasePtr = (ULONG64*)((PUCHAR)Process + 0x28);
    return *DirBasePtr;
}

// Map and unmap a physical page into virtual address space
PVOID MapPhysicalPage(PHYSICAL_ADDRESS PhysAddr) {
    return MmMapIoSpace(PhysAddr, PAGE_SIZE, MmNonCached);
}

void UnmapPhysicalPage(PVOID MappedAddr) {
    if (MappedAddr) {
        MmUnmapIoSpace(MappedAddr, PAGE_SIZE);
    }
}

PHYSICAL_ADDRESS GetPhysicalAddress(PEPROCESS Process, PVOID VirtualAddress) {
    ULONG64 DirectoryTableBase = GetProcessCR3(Process);
    if (!DirectoryTableBase || DirectoryTableBase == 0xFFFFFFFFFFFFFFFFULL) {
        return (PHYSICAL_ADDRESS){ .QuadPart = -1 };
    }

    ULONG64 Va = (ULONG64)VirtualAddress;
    ULONG64 Indexes[4] = {
        (Va >> 39) & 0x1FF,  // PML4
        (Va >> 30) & 0x1FF,  // PDPT
        (Va >> 21) & 0x1FF,  // PD
        (Va >> 12) & 0x1FF   // PT
    };

    ULONG64 PhysAddrVal = DirectoryTableBase;

    for (int level = 0; level < 4; level++) {
        PHYSICAL_ADDRESS DirPhys = { .QuadPart = PhysAddrVal };
        PVOID MappedDir = MapPhysicalPage(DirPhys);
        if (!MappedDir) return (PHYSICAL_ADDRESS){ .QuadPart = -1 };

        ULONG64* Entry = (ULONG64*)((PUCHAR)MappedDir + Indexes[level] * sizeof(ULONG64));
        ULONG64 EntryVal = *Entry;
        UnmapPhysicalPage(MappedDir);

        if ((EntryVal & PTE_PRESENT) == 0) {
            return (PHYSICAL_ADDRESS){ .QuadPart = -1 };
        }

        // Handle large pages (1GB or 2MB)
        if ((level == 1 || level == 2) && (EntryVal & PTE_PS)) {
            ULONG64 pageSize = (level == 1) ? (1ULL << 30) : (1ULL << 21);
            ULONG64 PhysBase = EntryVal & PTE_PFN_MASK;
            ULONG64 Offset = Va & (pageSize - 1);
            return (PHYSICAL_ADDRESS){ .QuadPart = PhysBase + Offset };
        }

        // Move to next level
        PhysAddrVal = EntryVal & PTE_PFN_MASK;
    }

    // 4KB page
    return (PHYSICAL_ADDRESS){ .QuadPart = PhysAddrVal + (Va & (PAGE_SIZE - 1)) };
}

// Write memory to a target process using direct page table manipulation
NTSTATUS WriteMemoryViaPageTables(
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    PVOID SourceBuffer,
    SIZE_T BufferSize
) {
    PUCHAR Src = (PUCHAR)SourceBuffer;
    PUCHAR DstVa = (PUCHAR)TargetAddress;
    SIZE_T Remaining = BufferSize;

    PVOID MappedPage = NULL;
    ULONG64 MappedPagePhysBase = 0;

    while (Remaining > 0) {
        PHYSICAL_ADDRESS PhysAddr = GetPhysicalAddress(TargetProcess, DstVa);
        if (PhysAddr.QuadPart == (ULONGLONG)-1LL) {
            if (MappedPage) UnmapPhysicalPage(MappedPage);
            return STATUS_ACCESS_VIOLATION;
        }

        ULONG64 OffsetInPage = (ULONG64)DstVa & (PAGE_SIZE - 1);
        ULONG64 PagePhysBase = PhysAddr.QuadPart - OffsetInPage;

        // Map a new physical page if needed
        if (!MappedPage || MappedPagePhysBase != PagePhysBase) {
            if (MappedPage) UnmapPhysicalPage(MappedPage);
            MappedPage = MapPhysicalPage((PHYSICAL_ADDRESS){ .QuadPart = PagePhysBase });
            if (!MappedPage) return STATUS_INSUFFICIENT_RESOURCES;
            MappedPagePhysBase = PagePhysBase;
        }

        SIZE_T ToCopy = min(Remaining, (SIZE_T)(PAGE_SIZE - OffsetInPage));
        RtlCopyMemory((PUCHAR)MappedPage + OffsetInPage, Src, ToCopy);

        Src += ToCopy;
        DstVa += ToCopy;
        Remaining -= ToCopy;
    }

    if (MappedPage) UnmapPhysicalPage(MappedPage);
    return STATUS_SUCCESS;
}
