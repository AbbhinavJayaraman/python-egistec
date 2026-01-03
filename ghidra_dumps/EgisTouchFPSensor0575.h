typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
#define unkbyte9   unsigned long long
#define unkbyte10   unsigned long long
#define unkbyte11   unsigned long long
#define unkbyte12   unsigned long long
#define unkbyte13   unsigned long long
#define unkbyte14   unsigned long long
#define unkbyte15   unsigned long long
#define unkbyte16   unsigned long long

#define unkuint9   unsigned long long
#define unkuint10   unsigned long long
#define unkuint11   unsigned long long
#define unkuint12   unsigned long long
#define unkuint13   unsigned long long
#define unkuint14   unsigned long long
#define unkuint15   unsigned long long
#define unkuint16   unsigned long long

#define unkint9   long long
#define unkint10   long long
#define unkint11   long long
#define unkint12   long long
#define unkint13   long long
#define unkint14   long long
#define unkint15   long long
#define unkint16   long long

#define unkfloat1   float
#define unkfloat2   float
#define unkfloat3   float
#define unkfloat5   double
#define unkfloat6   double
#define unkfloat7   double
#define unkfloat9   long double
#define unkfloat11   long double
#define unkfloat12   long double
#define unkfloat13   long double
#define unkfloat14   long double
#define unkfloat15   long double
#define unkfloat16   long double

#define BADSPACEBASE   void
#define code   void

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory:31;
    dword DataIsDirectory:1;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    dword EndAddress; // Apply ImageBaseOffset32 to see reference
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

typedef ulong DWORD;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef longlong INT_PTR;

typedef INT_PTR (*FARPROC)(void);

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef ushort WORD;

typedef WORD *LPWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef int BOOL;

typedef BOOL *LPBOOL;

typedef struct HINSTANCE__ *HINSTANCE;

typedef HINSTANCE HMODULE;

typedef void *LPCVOID;

typedef void *LPVOID;

typedef BYTE *LPBYTE;

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset:31;
    dword NameIsString:1;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    ImageBaseOffset32 Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    ImageBaseOffset32 AddressOfFunctions;
    ImageBaseOffset32 AddressOfNames;
    ImageBaseOffset32 AddressOfNameOrdinals;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulonglong ULONG_PTR;

typedef union _union_540 _union_540, *P_union_540;

typedef void *HANDLE;

typedef struct _struct_541 _struct_541, *P_struct_541;

typedef void *PVOID;

struct _struct_541 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_540 {
    struct _struct_541 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_540 u;
    HANDLE hEvent;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _STARTUPINFOW *LPSTARTUPINFOW;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT *PCONTEXT;

typedef ulonglong DWORD64;

typedef union _union_54 _union_54, *P_union_54;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_55 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_54 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_55 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_54 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef LONG LSTATUS;

typedef char CHAR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _RUNTIME_FUNCTION *PRUNTIME_FUNCTION;

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution=0,
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef struct _M128A *PM128A;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY {
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62 {
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

union _union_61 {
    PM128A FloatingContext[16];
    struct _struct_62 s;
};

typedef union _union_63 _union_63, *P_union_63;

typedef ulonglong *PDWORD64;

typedef struct _struct_64 _struct_64, *P_struct_64;

struct _struct_64 {
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_63 {
    PDWORD64 IntegerContext[16];
    struct _struct_64 s;
};

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

typedef struct _UNWIND_HISTORY_TABLE *PUNWIND_HISTORY_TABLE;

struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef CHAR *LPCSTR;

typedef LONG *PLONG;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef CHAR *LPSTR;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS *PKNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_61 u;
    union _union_63 u2;
};

typedef EXCEPTION_ROUTINE *PEXCEPTION_ROUTINE;

typedef DWORD LCID;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[135];
};




DWORD FUN_180001000(void);
void FUN_1800010e0(uint param_1,longlong param_2,undefined8 param_3,undefined8 param_4);
void FUN_180001290(int param_1,LPCSTR param_2);
uint FUN_1800013d0(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
uint FUN_180001460(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
uint FUN_180001560(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
uint FUN_180001670(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_180001700(longlong *param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4);
uint FUN_180001910(longlong *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
uint FUN_180001ad0(longlong *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
uint FUN_180001b30(longlong *param_1,int param_2,undefined8 param_3,undefined8 param_4);
void FUN_180001d10(longlong *param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4);
void FUN_180001f00(longlong *param_1,char param_2,undefined8 *param_3,ulonglong param_4);
uint FUN_1800025b0(longlong *param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4);
uint FUN_180002800(longlong param_1,undefined8 *param_2,ulonglong *param_3,undefined8 param_4);
uint FUN_1800028e0(longlong param_1,byte param_2,undefined8 param_3,undefined4 *param_4);
uint FUN_1800029d0(longlong *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5,undefined8 param_6,longlong param_7,longlong param_8);
undefined8 FUN_180002a40(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_180002a70(SIZE_T param_1);
undefined8 FUN_180002aa0(void);
undefined8 WbioQuerySensorInterface(undefined8 *param_1);
DWORD FUN_180002b0c(undefined1 *param_1,longlong param_2,char *param_3);
DWORD FUN_180002b70(undefined2 *param_1,longlong param_2,short *param_3);
void FUN_180002bdc(undefined1 *param_1,ulonglong param_2,longlong param_3,undefined8 param_4);
ulonglong FUN_180002c00(undefined *param_1,undefined1 *param_2,ulonglong param_3,longlong param_4,undefined8 param_5,undefined8 param_6);
ulonglong FUN_180002ce8(undefined1 *param_1,ulonglong param_2,longlong param_3,undefined8 param_4,undefined8 param_5);
void FUN_180002d58(undefined1 *param_1,ulonglong param_2,longlong param_3,undefined8 param_4);
undefined8 FUN_180002d70(undefined8 param_1,ulonglong param_2,undefined8 param_3,longlong param_4);
void FUN_180002d90(ulonglong param_1,longlong param_2,uint *param_3);
void FUN_180002e10(longlong param_1);
undefined8 * FUN_180002e40(undefined8 *param_1,undefined8 *param_2,ulonglong param_3);
undefined8 FUN_1800033a8(undefined8 param_1,int param_2,longlong param_3);
void entry(undefined8 param_1,int param_2,longlong param_3,undefined8 param_4);
ulonglong FUN_180003548(undefined8 param_1,int param_2,longlong param_3,undefined8 param_4);
void FUN_180003668(int param_1,undefined4 param_2,undefined4 param_3);
void FUN_18000375c(undefined8 param_1);
void FUN_180003764(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4);
void FUN_1800037cc(void);
void FUN_1800037ec(void);
DWORD * FUN_180003828(void);
void FUN_180003848(DWORD param_1);
DWORD * FUN_180003898(void);
undefined4 FUN_1800038b8(int param_1);
ulonglong FUN_180003908(undefined4 param_1,undefined **param_2);
longlong * FUN_180003a94(longlong *param_1,longlong *param_2);
undefined1 (*) [16] FUN_180003b50(undefined1 (*param_1) [16],byte param_2,ulonglong param_3);
void FUN_180003d7c(undefined **param_1,byte *param_2,longlong *param_3,WCHAR *param_4);
void FUN_1800047a4(byte param_1,undefined **param_2,int *param_3);
void FUN_1800047ec(byte param_1,int param_2,undefined **param_3,int *param_4);
void FUN_180004840(byte *param_1,int param_2,undefined **param_3,int *param_4,int *param_5);
void FUN_1800048d4(undefined8 param_1);
void FUN_180004920(void);
undefined8 FUN_1800049f4(void);
undefined4 FUN_180004b98(int param_1,undefined8 param_2);
undefined4 FUN_180004d64(int param_1,undefined8 param_2);
void FUN_180004d78(LPVOID param_1);
void FUN_180004eac(LPVOID param_1);
DWORD * FUN_180004ee8(void);
DWORD * FUN_180004f0c(void);
void FUN_180004f90(longlong param_1,longlong param_2);
undefined8 FUN_180005054(void);
void FUN_1800050d4(void);
void FUN_1800050f8(uint param_1);
void FUN_18000513c(uint param_1);
void FUN_180005154(void);
void FUN_18000529c(int param_1);
void FUN_1800052c4(void);
undefined8 FUN_1800052d4(void);
void FUN_18000536c(UINT param_1);
void FUN_180005378(void);
void FUN_1800053c4(undefined8 *param_1,undefined8 *param_2);
void FUN_180005424(undefined8 *param_1,undefined8 *param_2);
void FUN_180005460(void);
void FUN_18000546c(void);
void FUN_180005478(UINT param_1,int param_2,int param_3);
bool FUN_180005610(void);
void FUN_180005630(void);
undefined8 FUN_18000563c(void);
void FUN_18000596c(void);
undefined8 FUN_1800059e0(void);
void FUN_180005ad4(byte *param_1,undefined8 *param_2,byte *param_3,int *param_4,int *param_5);
undefined8 FUN_180005c9c(void);
void FUN_180005dd0(LPVOID param_1);
void FUN_180005e10(void);
LPSTR FUN_180005ebc(void);
void FUN_180005fb0(PCONTEXT param_1);
void FUN_180006020(PCONTEXT param_1);
void FUN_180006094(void);
void FUN_1800060b0(void);
void FUN_1800060cc(void);
void FUN_1800060e8(void);
undefined8 FUN_180006104(LPCRITICAL_SECTION param_1,DWORD param_2);
bool FUN_180006130(void);
void FUN_18000617c(void);
void __stdcall Sleep(DWORD dwMilliseconds);
void FUN_180006580(undefined4 param_1);
void FUN_1800065a0(undefined8 param_1);
LPVOID FUN_1800065c0(ulonglong param_1,ulonglong param_2);
LPVOID FUN_180006640(ulonglong param_1);
LPVOID FUN_1800066bc(LPVOID param_1,ulonglong param_2);
void FUN_180006740(void);
void FUN_180006778(void);
undefined8 FUN_1800067b0(PEXCEPTION_RECORD param_1,PVOID param_2,undefined8 param_3,longlong *param_4);
void FUN_180006994(void);
undefined8 FUN_18000699c(void);
void FUN_180006a34(void);
undefined ** FUN_180006a64(void);
void FUN_180006a6c(ulonglong param_1);
void FUN_180006ad4(int param_1,longlong param_2);
void FUN_180006b08(ulonglong param_1);
void FUN_180006b58(int param_1,longlong param_2);
undefined4 FUN_180006b78(longlong param_1);
byte FUN_180006ba0(uint param_1);
undefined4 FUN_180006c00(uint param_1,WCHAR *param_2,uint param_3);
void FUN_180006ce4(uint param_1,WCHAR *param_2,ulonglong param_3);
undefined8 FUN_1800074d8(uint param_1,LARGE_INTEGER param_2,DWORD param_3);
undefined8 FUN_1800075c0(uint param_1,LARGE_INTEGER param_2,DWORD param_3);
void FUN_180007654(undefined8 *param_1);
void FUN_1800076a8(int *param_1);
void FUN_180007734(LPVOID param_1);
int * FUN_1800078cc(int *param_1);
int * FUN_180007970(void);
int * FUN_1800079e8(undefined8 *param_1,int *param_2);
undefined8 FUN_180007a4c(void);
UINT FUN_180007a74(UINT param_1);
void FUN_180007af4(longlong param_1);
void FUN_180007b84(longlong param_1);
int * FUN_180007d68(void);
int FUN_180007e24(UINT param_1);
void FUN_180008068(UINT param_1,longlong param_2);
ushort FUN_180008318(uint param_1,longlong *param_2);
ushort FUN_18000835c(uint param_1);
char * FUN_1800083c0(ulonglong *param_1);
bool FUN_180008468(void);
DWORD FUN_180008480(int *param_1,undefined1 (*param_2) [16],ulonglong param_3,WCHAR param_4,longlong *param_5);
void FUN_18000860c(int *param_1,undefined1 (*param_2) [16],ulonglong param_3,WCHAR param_4);
void FUN_180008620(void);
undefined4 FUN_18000865c(LPWSTR param_1,byte *param_2,ulonglong param_3,longlong *param_4);
void FUN_1800087b0(LPWSTR param_1,byte *param_2,ulonglong param_3);
void FUN_1800087b8(int param_1);
void FUN_1800087fc(void);
undefined8 FUN_180008884(int param_1);
undefined4 FUN_180008944(void);
void FUN_1800089a8(int param_1);
void FUN_1800089c0(void);
undefined * FUN_180008a04(int param_1);
void FUN_180008a34(int param_1);
longlong FUN_180008cb0(longlong param_1,ulonglong param_2);
ulonglong FUN_180008d00(longlong param_1);
bool FUN_180008d50(short *param_1);
undefined4 FUN_180008d80(void);
PVOID FUN_180008dc4(PVOID param_1);
int FUN_180008ed0(PVOID param_1);
void FUN_180008ee8(void);
void FUN_180008f08(void);
undefined8 FUN_180008f28(undefined8 param_1);
void FUN_180008f5c(undefined8 param_1);
void FUN_180008f64(undefined8 param_1);
void FUN_180008f6c(void);
void FUN_180008f7c(undefined8 param_1);
undefined8 FUN_180008f9c(uint param_1);
void FUN_1800091d0(undefined8 param_1);
void FUN_1800091f0(PVOID param_1,PVOID param_2);
void FUN_180009220(void);
void FUN_180009240(void);
void FUN_180009250(void);
uint FUN_180009254(longlong *param_1,uint param_2,uint param_3,byte param_4);
void FUN_1800092d0(uint param_1);
LPVOID FUN_1800092e4(ulonglong param_1);
LPVOID FUN_18000939c(LPVOID param_1,ulonglong param_2);
LPVOID FUN_180009470(ulonglong param_1,ulonglong param_2,undefined4 *param_3);
int FUN_18000950c(void);
ulonglong FUN_1800095b4(int *param_1);
undefined8 FUN_180009600(int *param_1);
void FUN_18000967c(void);
int FUN_180009688(int param_1);
undefined8 FUN_180009770(uint param_1);
undefined8 FUN_180009808(uint param_1);
undefined8 FUN_1800098b4(uint param_1);
void FUN_180009928(uint param_1);
undefined2 FUN_180009954(undefined2 param_1);
void FUN_1800099c0(void);
void FUN_180009a10(longlong param_1);
void FUN_180009b1c(undefined8 *param_1);
void FUN_180009b88(undefined8 *param_1);
void FUN_180009f84(longlong *param_1,longlong param_2,uint param_3,LPCSTR param_4,int param_5,undefined8 param_6,int param_7,UINT param_8,int param_9);
void FUN_18000a270(longlong *param_1,longlong param_2,uint param_3,LPCSTR param_4,int param_5,undefined8 param_6,int param_7,UINT param_8,int param_9);
void FUN_18000a308(longlong *param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,UINT param_6,int param_7);
void FUN_18000a480(longlong *param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,UINT param_6,int param_7);
ushort FUN_18000a508(int param_1,ushort param_2,longlong *param_3);
void FUN_18000a5e4(void);
DWORD FUN_18000a62c(short *param_1,longlong param_2,short *param_3);
longlong FUN_18000a6b4(short *param_1);
DWORD FUN_18000a6d0(short *param_1,longlong param_2,short *param_3,longlong param_4);
int FUN_18000a79c(int param_1);
void FUN_18000a7dc(LPCWSTR param_1,undefined8 param_2,uint param_3);
undefined8 FUN_18000aa50(longlong param_1);
void FUN_18000aa8c(void);
undefined4 FUN_18000aae4(longlong param_1);
undefined4 FUN_18000ab70(longlong param_1);
void FUN_18000aba4(longlong param_1,DWORD param_2,LPCWSTR param_3,int param_4,LPWSTR param_5,int param_6);
int FUN_18000ac34(longlong param_1,ushort *param_2,longlong param_3);
undefined4 FUN_18000ac8c(int *param_1);
undefined4 FUN_18000ad08(int *param_1);
DWORD FUN_18000ad70(uint param_1);
void FUN_18000ae48(void);
void FUN_18000ae68(void);
int FUN_18000aec0(ulonglong *param_1,longlong param_2,ulonglong param_3);
ulonglong FUN_18000af88(uint param_1);
undefined8 FUN_18000b04c(uint param_1);
void FUN_18000b108(undefined8 *param_1);
void FUN_18000b140(uint *param_1,byte *param_2,longlong *param_3,undefined8 *param_4);
void FUN_18000b210(uint *param_1,byte *param_2,longlong *param_3);
void FUN_18000b2d8(uint *param_1,byte *param_2,longlong *param_3);
void thunk_FUN_18000b2e8(void);
void FUN_18000b2e8(void);
void FUN_18000b370(ushort *param_1,uint *param_2);
void FUN_18000b928(ushort *param_1,uint *param_2);
void FUN_18000bee0(ushort *param_1,ushort *param_2,byte *param_3,int param_4,int param_5,int param_6,int param_7,longlong *param_8);
void FUN_18000c744(ulonglong *param_1,ulonglong *param_2,ulonglong param_3,int param_4,uint param_5,int param_6);
void FUN_18000c768(ulonglong *param_1,ulonglong *param_2,ulonglong param_3,int param_4,uint param_5,int param_6,longlong *param_7);
DWORD FUN_18000c7e8(ulonglong *param_1,undefined1 *param_2,ulonglong param_3,uint param_4,int param_5,longlong *param_6);
ulonglong FUN_18000cb98(undefined1 *param_1,ulonglong param_2,int param_3,int param_4,int *param_5,char param_6,longlong *param_7);
void FUN_18000cd94(undefined8 *param_1,undefined1 *param_2,ulonglong param_3,int param_4,int param_5,longlong *param_6);
undefined4 FUN_18000ce8c(ulonglong *param_1,longlong param_2,int param_3,int *param_4,char param_5,longlong *param_6);
void FUN_18000cff0(undefined8 *param_1,ulonglong *param_2,longlong param_3,int param_4,longlong *param_5);
void FUN_18000d0c4(undefined8 *param_1,ulonglong *param_2,ulonglong param_3,int param_4,int param_5,longlong *param_6);
void FUN_18000d200(char *param_1,longlong *param_2);
void FUN_18000d2a0(int param_1,uint *param_2,byte *param_3,longlong *param_4);
void FUN_18000d2e8(byte *param_1,longlong *param_2);
void FUN_18000d37c(char *param_1,int param_2,uint *param_3);
ulonglong FUN_18000d5a0(int param_1);
uint FUN_18000d61c(uint param_1,longlong *param_2);
uint FUN_18000d770(uint param_1);
undefined1 (*) [16] FUN_18000d790(undefined1 (*param_1) [16],uint param_2);
DWORD FUN_18000d8d4(char *param_1,ulonglong param_2,int param_3,longlong param_4);
void FUN_18000d9a0(uint *param_1,uint *param_2);
void FUN_18000da70(undefined8 param_1,int *param_2,undefined1 *param_3,longlong param_4);
void FUN_18000db28(int *param_1,int param_2,uint param_3,short *param_4);
BOOL __stdcall IsProcessorFeaturePresent(DWORD ProcessorFeature);
void __stdcall RtlUnwindEx(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue,PCONTEXT ContextRecord,PUNWIND_HISTORY_TABLE HistoryTable);
void FUN_18000e610(undefined8 param_1,longlong param_2);
void FUN_18000e636(undefined8 *param_1,longlong param_2);
void FUN_18000e67f(void);
void FUN_18000e698(void);
void FUN_18000e6b1(undefined8 param_1,longlong param_2);
void FUN_18000e6d5(void);
void FUN_18000e6f0(undefined8 param_1,longlong param_2);
void FUN_18000e707(void);
void FUN_18000e720(void);
void FUN_18000e739(void);
bool FUN_18000e760(undefined8 *param_1);
void FUN_18000e780(void);
void FUN_18000e794(undefined8 param_1,longlong param_2);
void FUN_18000e7b2(void);
void FUN_18000e7cb(undefined8 param_1,longlong param_2);
void FUN_18000e7f3(void);
void FUN_18000e80c(void);
void FUN_18000e825(undefined8 param_1,longlong param_2);
void FUN_18000e83d(undefined8 param_1,longlong param_2);

