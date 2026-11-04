#ifndef THRESH_WINNT_SHIM
#define THRESH_WINNT_SHIM
#ifndef _WIN32
#include <cstdint>
typedef std::uint8_t  BYTE;
typedef std::uint16_t WORD;
typedef std::uint32_t DWORD;
typedef std::int32_t  LONG;
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_SCN_MEM_WRITE     0x80000000u
#define IMAGE_SCN_MEM_EXECUTE   0x20000000u

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc,
         e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    WORD e_res[4], e_oemid, e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD Machine, NumberOfSections;
    DWORD TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    WORD SizeOfOptionalHeader, Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD Magic;
    BYTE MajorLinkerVersion, MinorLinkerVersion;
    DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint,
         BaseOfCode, BaseOfData;
    std::uint64_t ImageBase;
    DWORD SectionAlignment, FileAlignment, MajorOperatingSystemVersion, MinorOperatingSystemVersion,
         MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion,
         Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    WORD Subsystem, DllCharacteristics;
    std::uint64_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    DWORD LoaderFlags, NumberOfRvaAndSizes;
    struct { DWORD VirtualAddress, Size; } DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union { DWORD PhysicalAddress, VirtualSize; } Misc;
    DWORD VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations,
          PointerToLinenumbers;
    WORD NumberOfRelocations, NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER;
#endif
#endif
