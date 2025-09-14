#include <ntddk.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PTE_PRESENT 0x1
#define PTE_PS 0x80
#define PTE_PFN_MASK 0xFFFFFFFFFF000ULL

// Retrieve the DirectoryTableBase (CR3) for Windows 11
ULONG64 GetProcessCR3(PEPROCESS Process) {
    // Verify the offset; 0x0288 is typical but should be confirmed
    ULONG64* DirBasePtr = (ULONG64*)((PUCHAR)Process + 0x0288);
    return *DirBasePtr;
}

PVOID MapPhysicalPage(PHYSICAL_ADDRESS PhysAddr) {
    return MmMapIoSpace(PhysAddr, PAGE_SIZE, MmNonCached);
}

void UnmapPhysicalPage(PVOID MappedAddr) {
    if (MappedAddr) {
        MmUnmapIoSpace(MappedAddr, PAGE_SIZE);
    }
}

// Walk page tables to get physical address
PHYSICAL_ADDRESS GetPhysicalAddress(PEPROCESS Process, PVOID VirtualAddress) {
    ULONG64 DirectoryTableBase = GetProcessCR3(Process);
    if (DirectoryTableBase == 0 || DirectoryTableBase == 0xFFFFFFFFFFFFFFFFULL) {
        return (PHYSICAL_ADDRESS){ .QuadPart = -1LL };
    }

    ULONG64 Va = (ULONG64)VirtualAddress;
    ULONG64 Indexes[4] = {
        (Va >> 39) & 0x1FF,
        (Va >> 30) & 0x1FF,
        (Va >> 21) & 0x1FF,
        (Va >> 12) & 0x1FF
    };

    ULONG64 PhysAddrVal = DirectoryTableBase; // PML4
    for (int level = 0; level < 4; level++) {
        PHYSICAL_ADDRESS DirPhys = { .QuadPart = PhysAddrVal };
        PVOID MappedDir = MapPhysicalPage(DirPhys);
        if (!MappedDir) return (PHYSICAL_ADDRESS){ .QuadPart = -1LL };

        ULONG64* Entry = (ULONG64*)((PUCHAR)MappedDir + Indexes[level] * sizeof(ULONG64));
        ULONG64 EntryVal = *Entry;
        UnmapPhysicalPage(MappedDir);

        if ((EntryVal & PTE_PRESENT) == 0) {
            return (PHYSICAL_ADDRESS){ .QuadPart = -1LL }; 
        }

        if (level < 3 && (EntryVal & PTE_PS)) {
            ULONG64 LargePagePhysBase = EntryVal & PTE_PFN_MASK;
            ULONG64 Offset = Va & ((1ULL << (12 + 9 * (3 - level))) - 1);
            ULONG64 PhysAddr = LargePagePhysBase + Offset;
            PHYSICAL_ADDRESS PhysAddrResult = { .QuadPart = PhysAddr };
            return PhysAddrResult;
        }

        PhysAddrVal = EntryVal & PTE_PFN_MASK;
    }

    ULONG64 Offset = Va & (PAGE_SIZE - 1);
    PHYSICAL_ADDRESS FinalPhys = { .QuadPart = PhysAddrVal + Offset };
    return FinalPhys;
}

NTSTATUS WriteMemoryViaPageTables(PEPROCESS TargetProcess, PVOID TargetAddress, PVOID SourceBuffer, SIZE_T BufferSize) {
    PUCHAR Src = (PUCHAR)SourceBuffer;
    PUCHAR DstVa = (PUCHAR)TargetAddress;
    SIZE_T Remaining = BufferSize;

    PVOID MappedPage = NULL;
    ULONG64 MappedPagePhysBase = 0;

    while (Remaining > 0) {
        PHYSICAL_ADDRESS PhysAddr = GetPhysicalAddress(TargetProcess, DstVa);
        if (PhysAddr.QuadPart == (ULONGLONG)-1LL) {
            if (MappedPage) {
                UnmapPhysicalPage(MappedPage);
            }
            return STATUS_ACCESS_VIOLATION;
        }

        ULONG64 OffsetInPage = (ULONG64)DstVa & (PAGE_SIZE - 1);
        ULONG64 PagePhysBase = PhysAddr.QuadPart - OffsetInPage;

        if (!MappedPage || MappedPagePhysBase != PagePhysBase) {
            if (MappedPage) {
                UnmapPhysicalPage(MappedPage);
            }
            MappedPage = MapPhysicalPage((PHYSICAL_ADDRESS){ .QuadPart = PagePhysBase });
            if (!MappedPage) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            MappedPagePhysBase = PagePhysBase;
        }

        SIZE_T ToCopy = min(Remaining, (SIZE_T)(PAGE_SIZE - OffsetInPage));
        RtlCopyMemory((PUCHAR)MappedPage + OffsetInPage, Src, ToCopy);

        Src += ToCopy;
        DstVa += ToCopy;
        Remaining -= ToCopy;
    }

    if (MappedPage) {
        UnmapPhysicalPage(MappedPage);
    }
    return STATUS_SUCCESS;
}
