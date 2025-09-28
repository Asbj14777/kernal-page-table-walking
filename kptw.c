#include <ntddk.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PTE_PRESENT 0x1
#define PTE_PS      0x80
#define PTE_PFN_MASK 0xFFFFFFFFFF000ULL

// Retrieve the DirectoryTableBase (CR3) for a given process
ULONG64 GetProcessCR3(PEPROCESS Process) {
    // Offset 0x28 for DirectoryTableBase in EPROCESS (embedded KPROCESS) on Windows 10/11
    ULONG64* DirBasePtr = (ULONG64*)((PUCHAR)Process + 0x28);
    return *DirBasePtr;
}

PEPROCESS
FindProcessByName(
    _In_opt_ const CHAR *ImageNameAscii
)
{
    if (ImageNameAscii == NULL) {
        return NULL;
    }

    PEPROCESS process = NULL;
    PEPROCESS nextProcess = NULL;

    for (nextProcess = PsGetNextProcess(NULL);
         nextProcess != NULL;
         nextProcess = PsGetNextProcess(nextProcess))
    {
        const CHAR *procName = PsGetProcessImageFileName(nextProcess);
        if (procName != NULL) {
            SIZE_T queryLen = strlen(ImageNameAscii);
            SIZE_T procLen = strnlen(procName, 16);
            if (queryLen == procLen) {
                BOOLEAN isMatch = TRUE;
                for (SIZE_T i = 0; i < queryLen; ++i) {
                    CHAR queryChar = ImageNameAscii[i];
                    CHAR procChar = procName[i];

                    if (queryChar >= 'A' && queryChar <= 'Z') {
                        queryChar += ('a' - 'A');
                    }
                    if (procChar >= 'A' && procChar <= 'Z') {
                        procChar += ('a' - 'A');
                    }

                    if (queryChar != procChar) {
                        isMatch = FALSE;
                        break;
                    }
                }

                if (isMatch) {
                    ObReferenceObject(nextProcess);
                    process = nextProcess;
                    break;
                }
            }
        }

        ObDereferenceObject(nextProcess);
    }

    return process;
}

NTSTATUS
MapUserBufferWithMdl(
    _In_ PVOID UserVa,
    _In_ SIZE_T Length,
    _Out_ PMDL *OutMdl,
    _Out_ PVOID *OutKernelVa
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMDL mdl = NULL;
    PVOID kernelVa = NULL;

    if (!UserVa || (Length == 0) || !OutMdl || !OutKernelVa) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }

    mdl = IoAllocateMdl(UserVa, (ULONG)Length, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        goto Cleanup;
    }

    kernelVa = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (kernelVa == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    *OutMdl = mdl;
    *OutKernelVa = kernelVa;
    return STATUS_SUCCESS;

Cleanup:
    if (mdl != NULL) {
        __try {
            MmUnlockPages(mdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        IoFreeMdl(mdl);
    }
    *OutMdl = NULL;
    *OutKernelVa = NULL;
    return status;
}

VOID
UnmapAndFreeMdl(
    _In_opt_ PMDL Mdl
)
{
    if (Mdl == NULL) {
        return;
    }

    __try {
        MmUnlockPages(Mdl);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    IoFreeMdl(Mdl);
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
    if (!TargetProcess || !TargetAddress || !SourceBuffer || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

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
