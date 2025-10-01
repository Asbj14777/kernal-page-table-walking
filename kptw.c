#include <ntddk.h>

#define PAGE_SIZE           0x1000ULL
#define PAGE_MASK           (~(PAGE_SIZE - 1))
#define PTE_PRESENT         0x1ULL
#define PTE_RW              0x2ULL
#define PTE_NX              (1ULL << 63)
#define PTE_PS              0x80ULL
#define PTE_PFN_MASK        0x000FFFFFFFFFF000ULL

#define CR3_CACHE_MAX       64
#define CR3_CACHE_TTL_MS    5000ULL

typedef struct _CR3_CACHE_ENTRY {
    HANDLE          Pid;
    UINT64          Cr3;
    LARGE_INTEGER   LastUsed;
    LARGE_INTEGER   Expiry;
} CR3_CACHE_ENTRY;

static CR3_CACHE_ENTRY g_Cr3Cache[CR3_CACHE_MAX];
static FAST_MUTEX g_Cr3CacheLock;

typedef enum _MEMORY_ACCESS_TYPE { MemRead, 
MemWrite } MEMORY_ACCESS_TYPE;

static VOID InitCr3Cache(void) {
    ExInitializeFastMutex(&g_Cr3CacheLock);
    RtlZeroMemory(g_Cr3Cache, sizeof(g_Cr3Cache));
}

static BOOLEAN IsCanonical(UINT64 va) {
    const UINT64 mask = (~0ULL) << 48;
    UINT64 sign = (va >> 47) & 1ULL;
    return sign ? ((va & mask) == mask) : ((va & mask) == 0);
}

static PVOID MapPhys(UINT64 physBase) {
    PHYSICAL_ADDRESS pa = { .QuadPart = physBase & PAGE_MASK };
    return MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
}

static VOID UnmapPhys(PVOID addr) {
    if (addr) MmUnmapIoSpace(addr, PAGE_SIZE);
}

static BOOLEAN ValidateCr3(UINT64 CandidateCr3) {
    if (!CandidateCr3) return FALSE;
    UINT64 samples[] = { 0x00007FF800000000ULL, 0xFFFFF80000000000ULL };
    for (int s = 0; s < ARRAYSIZE(samples); ++s) {
        UINT64 va = samples[s];
        if (!IsCanonical(va)) continue;
        UINT64 indexes[4] = {
            (va >> 39) & 0x1FF,
            (va >> 30) & 0x1FF,
            (va >> 21) & 0x1FF,
            (va >> 12) & 0x1FF
        };
        UINT64 tablePhys = CandidateCr3 & PTE_PFN_MASK;
        for (int level = 0; level < 4; ++level) {
            PULONG64 tbl = MapPhys(tablePhys);
            if (!tbl) return FALSE;
            UINT64 entry = tbl[indexes[level]];
            UnmapPhys(tbl);
            if (!(entry & PTE_PRESENT) || !(entry & PTE_RW)) return FALSE;
            if ((level == 1 || level == 2) && (entry & PTE_PS)) break;
            tablePhys = entry & PTE_PFN_MASK;
            if (!tablePhys) return FALSE;
        }
    }
    return TRUE;
}

static UINT64 LookupCr3Cache(HANDLE Pid) {
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    ExAcquireFastMutex(&g_Cr3CacheLock);
    for (int i = 0; i < CR3_CACHE_MAX; ++i) {
        if (g_Cr3Cache[i].Pid == Pid) {
            if (now.QuadPart < g_Cr3Cache[i].Expiry.QuadPart && ValidateCr3(g_Cr3Cache[i].Cr3)) {
                g_Cr3Cache[i].LastUsed = now;
                UINT64 cr3 = g_Cr3Cache[i].Cr3;
                ExReleaseFastMutex(&g_Cr3CacheLock);
                return cr3;
            }
            g_Cr3Cache[i].Pid = 0;
        }
    }
    ExReleaseFastMutex(&g_Cr3CacheLock);
    return 0;
}

static VOID InsertCr3Cache(HANDLE Pid, UINT64 Cr3) {
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    LARGE_INTEGER expiry = { .QuadPart = now.QuadPart + (LONGLONG)CR3_CACHE_TTL_MS * 10000ULL };
    ExAcquireFastMutex(&g_Cr3CacheLock);
    int emptyIdx = -1, lruIdx = 0;
    LARGE_INTEGER oldest = g_Cr3Cache[0].LastUsed;
    for (int i = 0; i < CR3_CACHE_MAX; ++i) {
        if (!g_Cr3Cache[i].Pid) emptyIdx = i;
        if (g_Cr3Cache[i].LastUsed.QuadPart < oldest.QuadPart) {
            oldest = g_Cr3Cache[i].LastUsed;
            lruIdx = i;
        }
    }
    int idx = (emptyIdx >= 0) ? emptyIdx : lruIdx;
    g_Cr3Cache[idx] = (CR3_CACHE_ENTRY){ .Pid = Pid, .Cr3 = Cr3, .LastUsed = now, .Expiry = expiry };
    ExReleaseFastMutex(&g_Cr3CacheLock);
}

static UINT64 GetProcessCr3(PEPROCESS Process) {
    if (!Process) return 0;
    HANDLE pid = PsGetProcessId(Process);
    UINT64 cached = LookupCr3Cache(pid);
    if (cached) return cached;
    UINT64 cr3Candidate = *(UINT64 *)((PUCHAR)Process + 0x28);
    if (!cr3Candidate || cr3Candidate == ~0ULL) return 0;
    if (ValidateCr3(cr3Candidate)) {
        InsertCr3Cache(pid, cr3Candidate);
        return cr3Candidate;
    }
    return 0;
}

static PHYSICAL_ADDRESS GetPhysicalAddressStrict(PEPROCESS Process, PVOID VirtualAddress, NTSTATUS *OutStatus) {
    PHYSICAL_ADDRESS invalid = { .QuadPart = (ULONGLONG)-1 };
    if (!Process || !VirtualAddress) { if (OutStatus) *OutStatus = STATUS_INVALID_PARAMETER; return invalid; }
    if (!IsCanonical((UINT64)VirtualAddress)) { if (OutStatus) *OutStatus = STATUS_INVALID_ADDRESS; return invalid; }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { if (OutStatus) *OutStatus = STATUS_INVALID_LEVEL; return invalid; }
    UINT64 cr3 = GetProcessCr3(Process);
    if (!cr3) { if (OutStatus) *OutStatus = STATUS_UNSUCCESSFUL; return invalid; }

    UINT64 va = (UINT64)VirtualAddress;
    UINT64 indexes[4] = { (va >> 39) & 0x1FF, (va >> 30) & 0x1FF, (va >> 21) & 0x1FF, (va >> 12) & 0x1FF };
    UINT64 tablePhys = cr3 & PTE_PFN_MASK;
    PVOID mapped = NULL;

    for (int level = 0; level < 4; ++level) {
        mapped = MapPhys(tablePhys);
        if (!mapped) { if (OutStatus) *OutStatus = STATUS_INSUFFICIENT_RESOURCES; return invalid; }
        UINT64 entry = ((UINT64 *)mapped)[indexes[level]];
        UnmapPhys(mapped);
        mapped = NULL;

        if (!(entry & PTE_PRESENT)) { if (OutStatus) *OutStatus = STATUS_ACCESS_VIOLATION; return invalid; }
        if (!(entry & PTE_RW)) { if (OutStatus) *OutStatus = STATUS_ACCESS_DENIED; return invalid; }
        if ((level == 1 || level == 2) && (entry & PTE_PS)) {
            if (entry & PTE_NX) { if (OutStatus) *OutStatus = STATUS_ACCESS_DENIED; return invalid; }
            UINT64 pageSize = (level == 1) ? (1ULL<<30) : (1ULL<<21);
            if (OutStatus) *OutStatus = STATUS_SUCCESS;
            return (PHYSICAL_ADDRESS){ .QuadPart = (entry & PTE_PFN_MASK) + (va & (pageSize-1)) };
        }
        tablePhys = entry & PTE_PFN_MASK;
        if (!tablePhys) { if (OutStatus) *OutStatus = STATUS_UNSUCCESSFUL; return invalid; }
    }

    mapped = MapPhys(tablePhys);
    if (!mapped) { if (OutStatus) *OutStatus = STATUS_INSUFFICIENT_RESOURCES; return invalid; }
    UINT64 pte = ((UINT64 *)mapped)[indexes[3]];
    UnmapPhys(mapped);
    if (!(pte & PTE_PRESENT)) { if (OutStatus) *OutStatus = STATUS_ACCESS_VIOLATION; return invalid; }
    if (!(pte & PTE_RW)) { if (OutStatus) *OutStatus = STATUS_ACCESS_DENIED; return invalid; }
    if (pte & PTE_NX) { if (OutStatus) *OutStatus = STATUS_ACCESS_DENIED; return invalid; }
    if (OutStatus) *OutStatus = STATUS_SUCCESS;
    return (PHYSICAL_ADDRESS){ .QuadPart = (pte & PTE_PFN_MASK) + (va & (PAGE_SIZE-1)) };
}

static NTSTATUS MapUserBufferWithMdl(PVOID UserVa, SIZE_T Length, PMDL *OutMdl, PVOID *OutKernelVa) {
    if (!UserVa || !Length || !OutMdl || !OutKernelVa) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;
    PMDL mdl = IoAllocateMdl(UserVa, (ULONG)Length, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;
    __try { MmProbeAndLockPages(mdl, UserMode, IoReadAccess); } __except(EXCEPTION_EXECUTE_HANDLER) { IoFreeMdl(mdl); return GetExceptionCode(); }
    PVOID kva = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (!kva) { MmUnlockPages(mdl); IoFreeMdl(mdl); return STATUS_INSUFFICIENT_RESOURCES; }
    *OutMdl = mdl; *OutKernelVa = kva;
    return STATUS_SUCCESS;
}

static VOID UnmapAndFreeMdl(PMDL Mdl) {
    if (!Mdl) return;
    __try { MmUnlockPages(Mdl); } __except(EXCEPTION_EXECUTE_HANDLER) {}
    IoFreeMdl(Mdl);
}

NTSTATUS AccessMemoryViaPageTablesSafe(
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    MEMORY_ACCESS_TYPE AccessType
) {
    if (!TargetProcess || !TargetAddress || !Buffer || BufferSize == 0)
        return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_LEVEL;

    NTSTATUS status = STATUS_SUCCESS;
    PUCHAR va = (PUCHAR)TargetAddress;
    PUCHAR buf = (PUCHAR)Buffer;
    SIZE_T remaining = BufferSize;

    while (remaining > 0) {
        NTSTATUS walkStatus = STATUS_UNSUCCESSFUL;
        PHYSICAL_ADDRESS phys = GetPhysicalAddressStrict(TargetProcess, va, &walkStatus);
        if (!NT_SUCCESS(walkStatus)) { status = walkStatus; break; }

     
        SIZE_T pageOffset = (UINT64)va & (PAGE_SIZE - 1);
        SIZE_T runLength = PAGE_SIZE - pageOffset;

     
        if (runLength > remaining)
            runLength = remaining;

 
        PMDL mdl = IoAllocateMdl(va, (ULONG)runLength, FALSE, FALSE, NULL);
        if (!mdl) { status = STATUS_INSUFFICIENT_RESOURCES; break; }

        __try {
       
            MmProbeAndLockPages(mdl, KernelMode,
                (AccessType == MemWrite) ? IoWriteAccess : IoReadAccess);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(mdl);
            status = GetExceptionCode();
            break;
        }

        PVOID mapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        if (!mapped) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        __try {
            if (AccessType == MemWrite) {
                RtlCopyMemory(mapped, buf, runLength);
            } else {
                RtlCopyMemory(buf, mapped, runLength);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }

        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        if (!NT_SUCCESS(status)) break;

        buf += runLength;
        va += runLength;
        remaining -= runLength;
    }

    return status;
}


#define ReadMemoryViaPageTables(TargetProcess, TargetAddress, Buffer, BufferSize) \
    AccessMemoryViaPageTablesSafe(TargetProcess, TargetAddress, Buffer, BufferSize, MemRead)

#define WriteMemoryViaPageTables(TargetProcess, TargetAddress, Buffer, BufferSize) \
    AccessMemoryViaPageTablesSafe(TargetProcess, TargetAddress, Buffer, BufferSize, MemWrite)




