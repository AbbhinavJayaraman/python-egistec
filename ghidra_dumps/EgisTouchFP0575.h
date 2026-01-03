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
typedef unsigned long long    undefined5;
typedef unsigned long long    undefined6;
typedef unsigned long long    undefined7;
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

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    dword EndAddress; // Apply ImageBaseOffset32 to see reference
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef RTTIBaseClassDescriptor *RTTIBaseClassDescriptor *32 __((image-base-relative));

typedef RTTIBaseClassDescriptor *32 __((image-base-relative)) *RTTIBaseClassDescriptor *32 __((image-base-relative)) *32 __((image-base-relative));

typedef struct PMD PMD, *PPMD;

struct PMD {
    int mdisp;
    int pdisp;
    int vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    ImageBaseOffset32 pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
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

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    RTTIBaseClassDescriptor *32 __((image-base-relative)) *32 __((image-base-relative)) pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef struct _BCryptBufferDesc _BCryptBufferDesc, *P_BCryptBufferDesc;

typedef struct _BCryptBufferDesc BCryptBufferDesc;

typedef ulong ULONG;

typedef struct _BCryptBuffer _BCryptBuffer, *P_BCryptBuffer;

typedef struct _BCryptBuffer *PBCryptBuffer;

typedef void *PVOID;

struct _BCryptBuffer {
    ULONG cbBuffer;
    ULONG BufferType;
    PVOID pvBuffer;
};

struct _BCryptBufferDesc {
    ULONG ulVersion;
    ULONG cBuffers;
    PBCryptBuffer pBuffers;
};

typedef PVOID BCRYPT_SECRET_HANDLE;

typedef PVOID BCRYPT_KEY_HANDLE;

typedef PVOID BCRYPT_HANDLE;

typedef PVOID BCRYPT_HASH_HANDLE;

typedef PVOID BCRYPT_ALG_HANDLE;

typedef long LONG;

typedef LONG NTSTATUS;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void *LPVOID;

typedef int BOOL;

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

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef struct _SYSTEMTIME SYSTEMTIME;

typedef ushort WORD;

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

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef BYTE *LPBYTE;

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

typedef struct _STARTUPINFOW *LPSTARTUPINFOW;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

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

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

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

typedef struct _OSVERSIONINFOEXW _OSVERSIONINFOEXW, *P_OSVERSIONINFOEXW;

struct _OSVERSIONINFOEXW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
    WORD wServicePackMajor;
    WORD wServicePackMinor;
    WORD wSuiteMask;
    BYTE wProductType;
    BYTE wReserved;
};

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

typedef struct _OSVERSIONINFOEXW *LPOSVERSIONINFOEXW;

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

typedef ULONGLONG DWORDLONG;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef CHAR *LPSTR;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS *PKNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_61 u;
    union _union_63 u2;
};

typedef EXCEPTION_ROUTINE *PEXCEPTION_ROUTINE;

typedef DWORD ACCESS_MASK;

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

typedef longlong INT_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[136];
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef INT_PTR (*FARPROC)(void);

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef uchar UCHAR;

typedef UCHAR *PUCHAR;

typedef DWORD *LPDWORD;

typedef WORD *LPWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef HANDLE HGLOBAL;

typedef BOOL *LPBOOL;

typedef struct HINSTANCE__ *HINSTANCE;

typedef HINSTANCE HMODULE;

typedef void *LPCVOID;

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

typedef struct HRSRC__ *HRSRC;

struct HRSRC__ {
    int unused;
};

typedef HANDLE HLOCAL;

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

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;




void FUN_180001000(void);
void FUN_180001020(void);
void FUN_18000103c(void);
bool FUN_180001060(PUCHAR param_1,ULONG param_2);
bool FUN_1800010d0(undefined8 *param_1,ULONG *param_2,uint param_3,PUCHAR param_4);
void FUN_1800011f0(undefined8 param_1,ULONG param_2,PUCHAR param_3);
bool FUN_180001220(PUCHAR param_1,ULONG param_2,undefined8 *param_3,ULONG *param_4,uint param_5,PUCHAR param_6,undefined8 *param_7);
bool FUN_180001330(PUCHAR param_1,ULONG param_2,undefined8 param_3,ULONG param_4,PUCHAR param_5);
NTSTATUS FUN_1800013c0(undefined8 *param_1,ULONG *param_2,undefined8 param_3,int *param_4,undefined8 param_5,PUCHAR param_6);
NTSTATUS FUN_1800014f0(undefined8 *param_1,ULONG *param_2,undefined8 param_3,int *param_4,undefined8 param_5,PUCHAR param_6);
NTSTATUS FUN_180001610(PUCHAR param_1,PUCHAR param_2,PVOID param_3,ULONG param_4,PUCHAR param_5,ULONG param_6);
bool FUN_1800017d0(undefined8 *param_1,undefined8 param_2,ULONG param_3,PUCHAR param_4);
bool FUN_180001860(undefined8 *param_1,undefined8 param_2,undefined8 param_3,PUCHAR param_4,undefined4 *param_5);
bool FUN_180001920(PUCHAR param_1);
bool FUN_180001a00(PUCHAR param_1,int param_2);
undefined4 *FUN_180001af0(uint param_1,uint param_2,undefined8 *param_3,undefined8 *param_4,undefined8 *param_5,uint *param_6);
undefined4 FUN_180001bb0(longlong param_1);
void FUN_180001bc0(HLOCAL param_1);
bool FUN_180001bd0(int *param_1,ULONG param_2,PUCHAR param_3,ULONG param_4,PUCHAR param_5,ULONG param_6,ULONG *param_7);
undefined8 FUN_180001d60(undefined8 *param_1,undefined8 param_2,undefined8 *param_3,ulonglong param_4);
bool FUN_180001ec0(undefined8 *param_1,int param_2,undefined8 *param_3,int param_4,PVOID param_5,ULONG param_6,PUCHAR param_7,ULONG param_8);
bool FUN_180001fc0(PUCHAR param_1,uint param_2,PUCHAR param_3,PUCHAR param_4,uint param_5,PUCHAR param_6,ULONG param_7,ULONG *param_8);
bool FUN_180002170(PUCHAR param_1,undefined8 param_2,PUCHAR param_3,PUCHAR param_4,uint param_5,PUCHAR param_6,ULONG param_7);
bool FUN_180002310(PUCHAR param_1,PUCHAR param_2,uint *param_3,uint *param_4,uint param_5);
bool thunk_FUN_180002310(PUCHAR param_1,PUCHAR param_2,uint *param_3,uint *param_4,uint param_5);
undefined8 FUN_180002550(PUCHAR param_1,undefined8 param_2,undefined8 param_3,undefined1 *param_4,undefined8 param_5,undefined8 *param_6);
UINT FUN_180002760(void);
undefined * FUN_180002a10(void);
void FUN_180002a60(undefined8 *param_1,undefined8 param_2,PUCHAR param_3);
longlong FUN_180002b10(uint param_1,longlong param_2);
int FUN_180002b20(int *param_1,int *param_2);
undefined8 FUN_180002b40(undefined8 *param_1,uint param_2,undefined8 *param_3,uint param_4,undefined4 *param_5,uint *param_6,longlong param_7);
bool FUN_180002ee0(PUCHAR param_1,PUCHAR param_2,uint *param_3,uint *param_4,uint param_5,PUCHAR param_6,uint *param_7);
undefined8 FUN_1800031b0(int *param_1,uint *param_2,uint *param_3,uint *param_4,uint *param_5,longlong param_6);
undefined8 FUN_180003590(undefined8 param_1,PUCHAR param_2);
undefined8 FUN_1800036d0(undefined8 param_1,PUCHAR param_2);
void FUN_180003810(undefined8 param_1,undefined8 *param_2,uint *param_3,uint *param_4,longlong param_5);
void FUN_180003a70(longlong param_1,uint *param_2,int param_3,undefined8 *param_4,longlong param_5);
void FUN_180003cb0(undefined8 *param_1,uint *param_2,uint *param_3,PUCHAR param_4);
void FUN_180003e10(undefined8 param_1,uint *param_2);
void FUN_180003e30(undefined *param_1,ULONG param_2,undefined8 *param_3,undefined4 *param_4);
void FUN_180004030(uint *param_1,uint param_2);
void FUN_1800041d0(PUCHAR param_1,uint param_2,undefined8 *param_3,undefined8 *param_4,char *param_5);
void FUN_1800043e0(undefined8 *param_1,int *param_2,undefined8 param_3,char *param_4);
void FUN_180004570(undefined8 param_1,uint param_2);
void FUN_180004590(uint *param_1,uint param_2);
void FUN_180004730(longlong param_1,uint param_2,ulonglong *param_3,int param_4,longlong param_5);
BOOL __stdcall InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount,DWORD Flags);
void FUN_1800049d0(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 *param_4,int *param_5);
void FUN_180004c80(undefined8 *param_1,undefined8 param_2,undefined8 param_3,int param_4,int param_5);
void FUN_180004d00(undefined8 param_1,longlong *param_2,uint *param_3);
void FUN_180004ff0(undefined8 param_1,uint *param_2,uint param_3);
ulonglong FUN_180005150(byte *param_1,int param_2,int param_3,int param_4);
void FUN_180005184(byte *param_1,int param_2,int param_3,int param_4);
int FUN_1800051c0(longlong param_1,uint param_2,int param_3,byte *param_4,int param_5);
char FUN_180005360(longlong param_1,longlong param_2,int param_3,int param_4,int param_5,int param_6,int param_7);
ulonglong FUN_180005660(byte *param_1,int param_2,uint param_3,int param_4,int param_5);
int FUN_180005690(byte *param_1,int param_2,uint param_3,int param_4,int param_5);
int FUN_180005724(longlong param_1,int param_2,byte *param_3,int param_4,uint param_5,int param_6);
ulonglong FUN_1800057a4(longlong param_1,longlong param_2,uint param_3,int param_4,int param_5,int param_6,int param_7);
void FUN_1800058b0(longlong param_1,int param_2,int param_3);
int FUN_180005ae0(byte *param_1,int param_2,int param_3);
void FUN_180005b14(byte *param_1,int param_2,int param_3,undefined1 *param_4,undefined1 *param_5);
void FUN_180005b34(byte *param_1,int param_2,int param_3,undefined1 *param_4,undefined1 *param_5,int param_6);
void FUN_180005d18(byte *param_1,int param_2,int param_3,undefined1 *param_4,undefined1 *param_5);
void FUN_180005d38(byte *param_1,int param_2,int param_3);
void FUN_180005e70(longlong param_1,uint param_2,int param_3,int param_4,uint param_5);
void FUN_1800060b8(byte *param_1,int param_2,int param_3,int param_4);
void FUN_18000610c(byte *param_1,int param_2,int param_3,int param_4);
void FUN_180006144(byte *param_1,int param_2,int param_3,int param_4);
void FUN_18000618c(byte *param_1,int param_2,int param_3,int param_4);
void FUN_18000623c(byte *param_1,int param_2,int param_3,int param_4);
undefined8 FUN_1800062ec(void);
LPCRITICAL_SECTION FUN_1800062f0(LPCRITICAL_SECTION param_1,LPCWSTR param_2);
void FUN_1800063e0(LPCRITICAL_SECTION param_1);
undefined8 FUN_1800064c0(longlong *param_1,longlong param_2,uint param_3);
void FUN_1800064d0(longlong param_1,undefined8 *param_2,uint param_3);
bool FUN_180006640(longlong param_1,PUCHAR param_2,ULONG param_3,PUCHAR param_4,ULONG param_5,ULONG *param_6);
void FUN_1800066ec(longlong *param_1);
void FUN_18000677c(longlong *param_1,LPCWSTR param_2);
bool FUN_18000682c(longlong param_1);
void FUN_180006b18(undefined8 *param_1,undefined8 param_2,undefined8 *param_3,int param_4,int param_5);
undefined8 FUN_180006d00(LPCRITICAL_SECTION param_1);
bool FUN_180006d10(longlong *param_1,undefined8 param_2,uint param_3,uint *param_4);
undefined8 FUN_180006d68(undefined8 param_1,LPCWSTR param_2,LPCVOID param_3,DWORD param_4);
void FUN_180006de0(LPCRITICAL_SECTION param_1);
undefined8 * FUN_180006f0c(undefined8 *param_1);
void FUN_180006f20(undefined8 *param_1);
undefined8 * FUN_180006f68(undefined8 *param_1,uint param_2);
void FUN_180006f98(longlong param_1,ulonglong *param_2,int param_3,undefined8 *param_4,int param_5,undefined4 *param_6);
void FUN_1800072b4(int param_1,PUCHAR param_2,ULONG param_3,undefined8 param_4,ULONG param_5,uint *param_6,uint *param_7,uint param_8);
void FUN_180007364(longlong param_1,uint *param_2,uint *param_3,uint param_4);
void FUN_180007430(longlong param_1,uint *param_2,uint *param_3,uint param_4);
ulonglong FUN_1800074fc(PUCHAR param_1,uint param_2,undefined8 *param_3,uint param_4,undefined8 *param_5,uint param_6);
void FUN_180007594(longlong param_1,undefined8 param_2,undefined *param_3);
void FUN_18000790c(longlong param_1,undefined8 *param_2,int param_3,undefined8 *param_4,int param_5);
bool FUN_180007b0c(PUCHAR param_1,uint param_2,ulonglong *param_3,uint param_4,undefined8 *param_5,uint param_6);
ulonglong FUN_180007bc0(void);
int FUN_180007e0c(undefined8 *param_1);
void FUN_180008010(byte *param_1,uint param_2,ulonglong param_3,int param_4);
byte FUN_1800081f0(byte param_1,byte *param_2,byte param_3);
int FUN_1800082d4(byte *param_1,byte *param_2,undefined1 *param_3,byte *param_4,undefined2 param_5,uint param_6);
undefined8 FUN_180008720(byte *param_1,byte *param_2,undefined1 *param_3,int param_4);
undefined8 FUN_180008814(void);
ulonglong FUN_1800089c0(int param_1);
byte FUN_180008acc(void);
void FUN_180008bf4(longlong param_1,int *param_2);
undefined8 FUN_1800092d4(void);
void FUN_180009360(void);
void FUN_18000938c(byte *param_1,uint param_2,uint param_3,longlong param_4,uint param_5);
ulonglong FUN_1800095e0(byte *param_1,uint param_2,uint param_3,undefined8 param_4,uint param_5);
void FUN_1800096d8(undefined8 param_1,int param_2,int param_3);
void FUN_180009748(undefined1 *param_1,int param_2);
byte FUN_1800097f8(void);
void FUN_180009964(undefined8 param_1,int param_2,int param_3);
void FUN_1800099d4(byte *param_1,uint param_2,uint param_3,uint param_4);
void FUN_180009a40(void);
undefined8 FUN_180009c04(void);
void FUN_180009d0c(void);
ulonglong FUN_180009f4c(void);
ulonglong FUN_18000a074(void);
void FUN_18000a1a0(void);
int FUN_18000a36c(int param_1);
void FUN_18000a43c(longlong param_1,int param_2,undefined8 param_3,int param_4,longlong param_5,longlong param_6);
ulonglong FUN_18000a49c(int *param_1);
undefined8 FUN_18000a82c(byte *param_1,uint param_2,uint param_3,undefined8 param_4,int *param_5);
undefined8 FUN_18000a93c(byte *param_1,uint *param_2);
void FUN_18000ac9c(void);
ulonglong FUN_18000b178(int *param_1,undefined4 *param_2,longlong *param_3,undefined4 *param_4,undefined4 *param_5,uint *param_6);
void FUN_18000b5d0(byte *param_1,int param_2);
undefined4 FUN_18000b638(int param_1);
void FUN_18000b670(undefined8 *param_1,int *param_2,undefined8 param_3);
undefined8 * FUN_18000b7b4(undefined8 *param_1);
void FUN_18000b8fc(undefined8 *param_1);
undefined8 * FUN_18000b950(undefined8 *param_1,uint param_2);
uint FUN_18000b980(longlong param_1,byte *param_2,uint param_3,uint param_4,uint param_5,int *param_6);
undefined8 FUN_18000b9e4(longlong *param_1,char *param_2,undefined8 *param_3,undefined4 *param_4,uint param_5);
longlong FUN_18000bb40(longlong param_1);
bool FUN_18000bb6c(longlong param_1,undefined8 param_2,undefined *param_3,undefined *param_4);
bool FUN_18000bd4c(longlong param_1);
bool FUN_18000bd74(longlong param_1);
bool FUN_18000bdac(longlong param_1);
bool FUN_18000bde4(longlong param_1);
undefined8 FUN_18000be1c(longlong param_1,char *param_2);
bool FUN_18000be70(longlong param_1,undefined8 param_2,undefined *param_3,undefined *param_4);
bool FUN_18000c038(longlong param_1);
undefined8 FUN_18000c060(longlong *param_1,uint *param_2);
bool FUN_18000c094(longlong *param_1,undefined1 param_2,char param_3);
void FUN_18000c0f8(longlong param_1,uint param_2,int param_3,undefined8 *param_4);
byte FUN_18000c220(longlong param_1,int param_2,int param_3,undefined8 param_4,int param_5);
byte FUN_18000c2a4(undefined1 param_1,undefined1 param_2,undefined8 param_3);
byte FUN_18000c2f4(undefined1 param_1,undefined8 param_2);
byte FUN_18000c334(void);
byte FUN_18000c360(undefined1 param_1,undefined1 param_2,undefined8 param_3);
byte FUN_18000c3b0(undefined1 param_1,undefined1 param_2);
byte FUN_18000c3f0(undefined1 param_1,undefined1 param_2,undefined8 param_3);
byte FUN_18000c440(undefined8 param_1,int param_2,int param_3);
byte FUN_18000c490(undefined8 param_1,int param_2,int param_3);
undefined8 FUN_18000c4e0(undefined1 param_1,byte param_2,byte param_3);
void FUN_18000c544(undefined8 param_1);
void FUN_18000c5a0(undefined8 param_1,undefined8 param_2);
void FUN_18000c5d0(undefined8 param_1);
int FUN_18000c5f8(undefined8 param_1,undefined8 param_2);
void FUN_18000c80c(undefined8 param_1,undefined2 param_2,undefined8 param_3);
void FUN_18000c82c(void);
undefined8 FUN_18000c87c(int param_1,longlong param_2,undefined4 *param_3,undefined8 param_4);
void FUN_18000c8fc(void);
undefined8 FUN_18000c974(undefined8 param_1);
uint FUN_18000c998(undefined8 param_1,undefined8 param_2,undefined8 param_3);
void FUN_18000ca00(undefined8 *param_1);
undefined8 * FUN_18000ca58(undefined8 *param_1,byte param_2);
undefined8 * FUN_18000ca80(undefined8 *param_1,uint param_2);
uint FUN_18000cab0(longlong param_1);
uint FUN_18000cce0(undefined8 param_1,undefined8 param_2,undefined8 *param_3);
void FUN_18000ce6c(undefined8 param_1);
void FUN_18000ce90(undefined8 param_1,undefined4 param_2);
void FUN_18000cec0(undefined8 param_1,undefined4 param_2);
void FUN_18000cef0(undefined8 param_1);
void FUN_18000cf10(undefined8 param_1);
void FUN_18000cf34(undefined8 param_1);
void FUN_18000cf58(undefined8 param_1);
void FUN_18000cf7c(undefined8 param_1);
undefined8 FUN_18000cfa0(longlong param_1,longlong param_2);
undefined8 FUN_18000d084(undefined8 param_1);
int FUN_18000d0a8(longlong param_1,undefined8 param_2,undefined8 param_3);
undefined8 FUN_18000d268(longlong param_1,undefined8 param_2,int param_3);
undefined8 FUN_18000d404(longlong param_1,undefined8 param_2,int param_3);
void FUN_18000d634(longlong param_1,undefined8 param_2);
void FUN_18000d70c(longlong param_1,longlong param_2);
void FUN_18000dad8(longlong param_1,undefined8 param_2);
undefined8 FUN_18000e4c0(longlong param_1);
undefined8 FUN_18000e54c(longlong param_1);
undefined8 FUN_18000e5d8(longlong param_1);
void FUN_18000e69c(longlong param_1);
void FUN_18000e724(longlong param_1,int param_2);
void FUN_18000e738(longlong param_1,int param_2);
void FUN_18000e7a8(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined4 param_4);
void FUN_18000e7dc(undefined8 param_1,undefined2 param_2,undefined8 param_3,wchar_t *param_4);
void FUN_18000e850(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined4 param_4);
undefined8 * FUN_18000e894(undefined8 *param_1,undefined8 param_2,undefined8 param_3);
undefined8 * FUN_18000ea0c(undefined8 *param_1,longlong param_2,undefined8 param_3,uint *param_4);
void FUN_18000ea94(undefined8 *param_1);
undefined8 * FUN_18000eb14(undefined8 *param_1,uint param_2);
undefined8 * FUN_18000eb54(undefined8 *param_1,uint param_2);
uint FUN_18000eb84(longlong *param_1);
undefined8 FUN_18000f024(longlong *param_1);
int FUN_18000f334(longlong *param_1);
int FUN_18000f4ac(longlong *param_1);
void FUN_18000f8e8(undefined8 param_1,byte *param_2,int param_3,int param_4,int param_5,uint *param_6,uint *param_7);
void FUN_18000f9e0(LPVOID param_1);
void FUN_18000fa74(longlong param_1,undefined *param_2);
int FUN_18000fd18(longlong param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4,undefined4 param_5,undefined4 param_6,undefined8 param_7);
undefined8 FUN_18000fe28(longlong *param_1);
char FUN_18000fe60(longlong param_1,char *param_2,int param_3,int param_4);
undefined8 FUN_180010040(longlong param_1,ushort *param_2,uint *param_3);
undefined8 FUN_1800100ac(longlong param_1,undefined1 (*param_2) [16],uint *param_3);
void FUN_1800101a0(longlong *param_1);
undefined8 FUN_180010384(longlong param_1,undefined1 (*param_2) [16]);
void FUN_18001050c(longlong *param_1,undefined8 param_2,int param_3);
undefined4 FUN_1800106c0(longlong *param_1,undefined1 *param_2);
undefined8 FUN_1800107d0(longlong *param_1,undefined8 param_2,longlong param_3,undefined4 *param_4);
void FUN_180010c10(longlong *param_1,int param_2);
bool FUN_180010da8(longlong param_1,byte *param_2,int param_3,int param_4,char param_5);
void FUN_180010f58(longlong *param_1);
int FUN_1800112d8(longlong param_1,undefined8 param_2,undefined4 param_3);
undefined8 FUN_1800114a0(longlong param_1,undefined1 *param_2);
undefined4 FUN_1800114d4(longlong param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4);
undefined4 FUN_180011504(longlong param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4);
int FUN_18001153c(longlong *param_1);
int FUN_1800117c8(longlong *param_1);
void FUN_18001199c(longlong param_1);
int FUN_180011b1c(longlong param_1);
undefined4 FUN_180011c6c(longlong *param_1,uint *param_2);
undefined4 FUN_180011d80(longlong *param_1,byte param_2,undefined1 *param_3);
int FUN_180011ea0(longlong *param_1,longlong param_2,undefined1 *param_3,uint param_4);
void FUN_18001200c(longlong param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,undefined8 param_5);
undefined8 FUN_18001203c(longlong *param_1);
undefined8 FUN_180012160(longlong param_1);
undefined8 FUN_180012238(longlong param_1);
undefined8 FUN_180012274(longlong *param_1);
void FUN_180012444(longlong param_1);
void FUN_180012474(longlong *param_1,int param_2);
undefined4 FUN_1800126a0(longlong *param_1,undefined1 param_2);
void FUN_1800127a8(longlong param_1,undefined8 *param_2,longlong param_3);
undefined8 FUN_180012908(longlong param_1);
undefined8 FUN_180012a64(void);
void FUN_180012aac(longlong param_1);
undefined4 FUN_180012af0(longlong *param_1,byte param_2,undefined1 param_3);
int FUN_180012c00(longlong *param_1,undefined1 param_2,byte param_3,byte param_4);
int FUN_180012c98(longlong *param_1,longlong param_2,undefined1 *param_3,uint param_4);
void FUN_180012e04(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined4 param_4);
void FUN_180012e54(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined *param_4);
void FUN_180012fe0(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined *param_4);
bool FUN_180013034(longlong param_1,int param_2,int param_3,int param_4,int param_5,int param_6);
bool FUN_180013168(longlong param_1,int param_2,int param_3,int param_4,int param_5,int param_6);
ulonglong FUN_180013278(undefined8 *param_1,int param_2,int param_3);
void FUN_1800133a8(longlong param_1,int param_2,int param_3,byte param_4,char param_5);
void FUN_1800134d0(longlong param_1,int param_2,int param_3,byte param_4,byte param_5);
undefined8 FUN_180013504(byte *param_1,int param_2,byte *param_3,byte *param_4,int param_5);
uint FUN_180013590(byte *param_1,int param_2,int param_3,int param_4);
char FUN_1800137e4(longlong *param_1,int param_2,int param_3,int param_4);
ulonglong FUN_180013898(longlong param_1,int param_2,uint param_3);
int FUN_1800138e0(byte *param_1,uint param_2,uint param_3,undefined4 *param_4,int param_5);
LPVOID FUN_180013b54(int param_1,int param_2);
ulonglong FUN_180013bbc(int param_1,int param_2,longlong param_3,longlong param_4,byte param_5);
void FUN_180013d2c(int param_1,int param_2,longlong param_3,int param_4,int param_5,longlong param_6,longlong param_7,uint param_8);
void FUN_18001456c(int param_1,int param_2,longlong param_3,longlong param_4,int param_5);
void FUN_18001497c(uint param_1,int param_2,longlong param_3);
void FUN_180014b1c(int param_1,int param_2,longlong param_3,int param_4);
int thunk_FUN_1800138e0(byte *param_1,uint param_2,uint param_3,undefined4 *param_4,int param_5);
void FUN_180014dac(byte *param_1,uint param_2,uint param_3,int *param_4,int *param_5,int param_6);
void FUN_18001542c(byte *param_1,int param_2,int param_3,undefined4 *param_4);
undefined8 *FUN_180015480(undefined8 *param_1,undefined2 param_2,longlong param_3,undefined8 param_4,uint *param_5);
undefined8 * FUN_1800154fc(undefined8 *param_1,longlong param_2,undefined8 param_3);
undefined8 *FUN_180015610(undefined8 *param_1,undefined2 param_2,longlong param_3,undefined8 param_4,uint *param_5);
void FUN_1800156e4(undefined8 *param_1);
undefined8 * FUN_180015730(undefined8 *param_1,uint param_2);
undefined8 * FUN_18001576c(undefined8 *param_1,uint param_2);
undefined8 * FUN_1800157a8(undefined8 *param_1,uint param_2);
void FUN_1800157d8(longlong *param_1);
void FUN_180015bb0(longlong *param_1);
void FUN_180015c44(longlong *param_1,undefined8 *param_2,int param_3,uint *param_4,int param_5);
void FUN_180016018(void);
undefined4 FUN_18001601c(longlong param_1,undefined4 *param_2);
int FUN_1800160b0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,undefined4 param_5,undefined4 param_6,undefined8 param_7);
undefined8 FUN_1800161a4(longlong *param_1,undefined1 (*param_2) [16],uint *param_3);
void FUN_1800162d0(longlong param_1);
ulonglong FUN_18001636c(longlong param_1,undefined1 (*param_2) [16]);
undefined4 FUN_180016468(longlong param_1,undefined8 *param_2,int *param_3);
undefined4 FUN_1800166a8(longlong *param_1,undefined8 *param_2,uint *param_3);
int FUN_1800168c8(longlong *param_1,undefined8 *param_2,uint param_3);
undefined4 FUN_180016a54(longlong *param_1,undefined1 *param_2);
undefined4 FUN_180016b70(longlong *param_1,undefined8 param_2,undefined8 *param_3,undefined4 *param_4);
undefined8 FUN_180016dbc(longlong *param_1);
ulonglong FUN_180016f18(longlong param_1,HMODULE param_2,undefined8 param_3,undefined4 param_4);
undefined4 FUN_180017010(longlong param_1,undefined8 param_2,undefined4 param_3);
undefined4 FUN_1800170cc(longlong param_1);
undefined4 FUN_180017168(longlong *param_1,undefined8 *param_2,uint param_3);
undefined4 FUN_180017290(longlong *param_1,undefined8 *param_2,uint param_3);
undefined4 FUN_1800173b8(longlong *param_1,undefined8 param_2,int param_3);
bool FUN_180017568(undefined8 param_1,LPCWSTR param_2,undefined1 *param_3);
void FUN_1800175b8(longlong *param_1);
bool FUN_1800178d8(undefined8 param_1,LPCWSTR param_2,undefined8 param_3,undefined4 param_4);
undefined4 FUN_180017944(longlong *param_1,byte param_2,byte param_3,undefined8 param_4);
undefined4 FUN_180017a64(longlong *param_1,uint *param_2);
undefined4 FUN_180017b84(longlong *param_1,byte param_2,undefined1 *param_3);
int FUN_180017cb4(longlong *param_1,ulonglong param_2,undefined8 *param_3,uint param_4);
undefined4 FUN_180017f64(longlong *param_1,undefined8 param_2,undefined4 param_3);
int FUN_180018024(longlong *param_1);
int FUN_1800181e8(longlong *param_1);
int FUN_180018284(longlong *param_1);
ulonglong FUN_180018440(longlong param_1);
undefined4 FUN_1800184d4(longlong *param_1,undefined4 *param_2,longlong param_3,undefined1 *param_4,uint param_5,undefined8 *param_6);
undefined4 FUN_1800186bc(longlong param_1,int param_2);
undefined4 FUN_1800187a0(longlong *param_1,undefined1 param_2);
undefined8 FUN_1800188b4(longlong param_1,undefined8 *param_2,longlong param_3);
undefined4 FUN_1800189b8(longlong param_1);
undefined4 FUN_180018a70(longlong param_1);
bool FUN_180018b28(undefined8 param_1,LPCWSTR param_2,undefined1 param_3);
bool FUN_180018b70(undefined8 param_1,LPCWSTR param_2,undefined8 param_3,undefined4 param_4);
undefined4 FUN_180018bd0(longlong *param_1,byte param_2,byte param_3,undefined8 param_4);
undefined4 FUN_180018d9c(longlong *param_1,byte param_2,undefined1 param_3);
int FUN_180018f04(longlong *param_1,ulonglong param_2,undefined8 *param_3,uint param_4);
undefined4 FUN_18001925c(longlong *param_1,undefined8 param_2,undefined4 param_3);
bool FUN_1800193d4(longlong param_1,byte param_2,byte param_3,undefined8 *param_4);
bool FUN_1800193fc(longlong param_1,byte param_2,byte param_3,undefined8 *param_4);
bool FUN_18001942c(longlong param_1,byte param_2,byte param_3,undefined8 *param_4);
bool FUN_180019454(longlong param_1,byte param_2,byte param_3,undefined8 *param_4);
bool FUN_180019484(longlong param_1,undefined8 *param_2,int param_3,int param_4);
bool FUN_1800194a4(longlong param_1,byte param_2,undefined1 *param_3);
bool FUN_1800194c0(longlong param_1,undefined8 param_2,undefined4 param_3);
bool FUN_1800194dc(longlong param_1);
bool FUN_1800194f8(longlong param_1,byte param_2,undefined1 param_3);
bool FUN_180019514(longlong param_1,undefined8 param_2,undefined4 param_3);
undefined8 * FUN_180019530(undefined8 *param_1);
void FUN_1800195a4(undefined8 *param_1);
undefined8 * FUN_180019618(undefined8 *param_1,uint param_2);
bool FUN_180019648(longlong param_1,DWORD param_2);
uint FUN_180019704(longlong param_1,longlong param_2,undefined8 *param_3);
void FUN_180019800(undefined8 param_1);
void FUN_180019824(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,undefined4 param_5);
undefined8 FUN_18001987c(undefined8 param_1);
int FUN_1800198a0(longlong param_1,longlong param_2,longlong param_3);
void FUN_180019ab8(longlong param_1);
void FUN_180019af4(longlong param_1,undefined8 param_2,longlong param_3,int param_4,undefined8 param_5);
void FUN_18001a268(longlong param_1);
void FUN_18001a2c4(longlong param_1);
void FUN_18001a30c(longlong param_1);
void FUN_18001a360(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined8 param_4);
undefined8 * FUN_18001a3c0(undefined8 *param_1,undefined8 param_2);
void FUN_18001a3f8(longlong param_1);
void FUN_18001a42c(undefined8 *param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5);
undefined8 FUN_18001a4c8(longlong param_1,int param_2);
void FUN_18001a520(undefined8 *param_1);
void FUN_18001a820(undefined8 *param_1,undefined8 *param_2,uint param_3,int param_4,int param_5,int param_6,undefined4 *param_7);
int FUN_18001a980(undefined8 *param_1,longlong param_2,longlong param_3,longlong *param_4,int param_5,int param_6,int param_7,undefined4 *param_8);
void FUN_18001ab04(undefined8 *param_1);
void FUN_18001ae74(longlong param_1,undefined8 param_2,undefined8 param_3,int param_4,undefined4 *param_5);
void FUN_18001b078(undefined8 *param_1);
void FUN_18001b1bc(longlong param_1);
void FUN_18001b224(undefined8 param_1,undefined4 *param_2,undefined8 *param_3,undefined8 *param_4,undefined8 *param_5,undefined8 *param_6);
void FUN_18001b30c(undefined8 param_1,undefined4 *param_2,undefined8 *param_3,undefined8 *param_4,undefined8 *param_5,undefined8 *param_6);
void FUN_18001b3e4(ushort param_1,undefined2 param_2,WORD param_3);
void FUN_18001b4ac(undefined8 param_1,undefined8 param_2,longlong param_3,undefined8 param_4,undefined4 *param_5,int param_6,int param_7,longlong *param_8);
void FUN_18001b81c(undefined8 param_1,longlong param_2,undefined8 param_3,char *param_4,undefined4 *param_5,int param_6,int param_7,longlong *param_8);
short * FUN_18001ba38(short *param_1,LPCWSTR param_2);
undefined8 * FUN_18001ba70(undefined8 *param_1,undefined8 param_2,undefined8 param_3);
void FUN_18001bc00(undefined8 *param_1);
undefined8 * FUN_18001bc98(undefined8 *param_1,uint param_2);
void FUN_18001bcc8(longlong param_1,int param_2);
int FUN_18001bd8c(longlong *param_1);
void FUN_18001bec8(longlong param_1);
void FUN_18001bf68(longlong *param_1,undefined1 param_2,int *param_3);
void FUN_18001c8c0(longlong *param_1,int param_2,ulonglong *param_3,uint param_4,undefined8 *param_5,uint param_6,uint *param_7);
undefined8 FUN_18001cad0(longlong *param_1,int param_2,int param_3,int param_4);
void FUN_18001cd4c(longlong param_1,undefined1 param_2);
undefined8 FUN_18001ce28(longlong param_1,byte param_2);
void FUN_18001cf0c(longlong param_1);
void FUN_18001cf4c(longlong param_1);
undefined8 FUN_18001cf90(longlong param_1);
void FUN_18001cfa0(undefined8 param_1,undefined4 *param_2,uint *param_3);
undefined8 FUN_18001d084(undefined8 param_1,undefined1 (*param_2) [16],uint *param_3);
undefined8 * FUN_18001d0e8(undefined8 *param_1);
void FUN_18001d19c(longlong param_1);
undefined8 FUN_18001d85c(longlong param_1);
undefined4 FUN_18001d8a4(undefined8 param_1,longlong param_2);
undefined8 FUN_18001d934(undefined *param_1,undefined8 param_2,ulonglong param_3,ulonglong param_4,ulonglong param_5,ulonglong param_6,undefined4 *param_7);
void FUN_18001daa0(longlong param_1,undefined4 param_2,undefined4 param_3);
uint FUN_18001db48(undefined8 param_1,undefined8 param_2,undefined8 *param_3);
void FUN_18001dd30(undefined8 param_1);
void FUN_18001dd88(longlong param_1);
void FUN_18001ddd0(longlong param_1,undefined8 param_2);
void FUN_18001df4c(longlong param_1,longlong param_2);
void FUN_18001e06c(LPVOID param_1,longlong param_2);
void FUN_18001e474(longlong param_1,longlong param_2);
void FUN_18001e504(longlong param_1,undefined8 param_2);
void FUN_18001e654(longlong param_1,undefined8 param_2);
void FUN_18001e708(longlong param_1,undefined8 param_2);
void FUN_18001e7b8(longlong param_1,undefined8 param_2);
void FUN_18001e884(longlong param_1,undefined8 param_2);
void FUN_18001e9c4(longlong param_1);
void FUN_18001ef60(longlong param_1,undefined8 param_2);
void FUN_18001f0fc(undefined8 param_1,undefined8 param_2);
void FUN_18001f158(longlong param_1,undefined8 param_2);
void FUN_18001f1e4(longlong param_1,undefined8 param_2);
void FUN_18001f27c(longlong param_1,undefined8 param_2);
void FUN_18001f334(longlong param_1,undefined8 param_2);
void FUN_18001f4ec(longlong param_1,undefined8 param_2);
void FUN_18001f634(undefined8 param_1,undefined8 param_2);
void FUN_18001f690(longlong param_1,undefined8 param_2);
bool FUN_18001f7a8(longlong param_1,longlong param_2,int param_3);
void FUN_18001f828(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined8 param_4);
void FUN_18001f86c(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined4 param_4);
void FUN_18001f8b0(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined4 param_4);
void FUN_18001f904(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined8 param_4);
void FUN_18001f938(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined8 param_4);
void FUN_18001f97c(undefined8 param_1,undefined2 param_2,undefined8 param_3,undefined *param_4);
ulonglong FxDriverEntryUm(uint *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
ulonglong FUN_18001fa00(uint *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001fbfc(longlong param_1,undefined8 param_2,undefined8 param_3);
void TraceMessage(void);
void FUN_18001fcb8(LPVOID param_1);
LPVOID FUN_18001fcf8(ulonglong param_1);
undefined8 FUN_18001fdb0(undefined8 param_1,ulonglong param_2,undefined8 param_3,longlong param_4);
void FUN_18001fdd0(ulonglong param_1,longlong param_2,uint *param_3);
void FUN_18001fe50(longlong param_1);
undefined8 * FUN_18001fe80(undefined8 *param_1,undefined8 *param_2,ulonglong param_3);
undefined1 (*) [16] FUN_180020400(undefined1 (*param_1) [16],byte param_2,ulonglong param_3);
LPVOID FUN_18002062c(ulonglong param_1,ulonglong param_2);
LPVOID FUN_180020670(LPVOID param_1,ulonglong param_2);
void thunk_FUN_18001fcb8(LPVOID param_1);
undefined8 * FUN_18002074c(undefined8 *param_1,longlong param_2);
void FUN_180020780(ulonglong param_1);
undefined8 * FUN_1800207ec(undefined8 *param_1,uint param_2);
undefined4 FUN_180020828(void);
PVOID FUN_18002086c(PVOID param_1);
int FUN_180020978(PVOID param_1);
ushort * FUN_180020990(ushort *param_1,ushort param_2);
int FUN_180020a30(ulonglong *param_1,longlong param_2,ulonglong param_3);
void FUN_180020af8(undefined8 param_1);
void FUN_180020b44(void);
void FUN_180020c30(void);
double FUN_180020c80(double param_1);
void thunk_FUN_180020d88(void);
void FUN_180020d88(void);
undefined1 (*) [16] FUN_180020e10(undefined1 (*param_1) [16],uint param_2);
void FUN_180020f54(void);
undefined4 FUN_180020f80(undefined1 *param_1,WCHAR *param_2,undefined8 param_3,undefined8 param_4);
longlong * FUN_180021044(longlong *param_1,longlong *param_2);
uint FUN_1800210ec(longlong *param_1,byte *param_2,undefined8 *param_3,uint param_4,uint param_5);
void FUN_180021328(byte *param_1,undefined8 *param_2,uint param_3);
undefined8 FUN_180021358(undefined8 param_1,int param_2,longlong param_3);
void entry(undefined8 param_1,int param_2,longlong param_3,undefined8 param_4);
ulonglong FUN_1800214f8(undefined8 param_1,int param_2,longlong param_3,undefined8 param_4);
DWORD * FUN_180021618(void);
void FUN_180021638(DWORD param_1);
DWORD * FUN_180021688(void);
undefined4 FUN_1800216a8(int param_1);
bool FUN_1800216f8(void);
void FUN_180021718(void);
undefined8 FUN_180021724(undefined8 param_1);
void FUN_180021758(undefined8 param_1);
void FUN_180021760(uint param_1);
void FUN_1800217a4(uint param_1);
void FUN_1800217bc(void);
void FUN_180021904(int param_1);
void FUN_18002192c(void);
undefined8 FUN_18002193c(void);
void FUN_1800219d4(UINT param_1);
void FUN_1800219e0(void);
void FUN_180021a2c(undefined8 *param_1,undefined8 *param_2);
void FUN_180021a8c(undefined8 *param_1,undefined8 *param_2);
void FUN_180021ac8(void);
void FUN_180021ad4(void);
void FUN_180021ae0(UINT param_1,int param_2,int param_3);
void FUN_180021c78(void);
undefined * FUN_180021cbc(int param_1);
void FUN_180021cec(int param_1);
undefined8 FUN_180021f5c(void);
LPVOID FUN_180022100(ulonglong param_1,ulonglong param_2,undefined4 *param_3);
undefined8 * FUN_18002219c(undefined8 *param_1,undefined8 *param_2);
undefined8 * FUN_1800221b8(undefined8 *param_1,longlong param_2);
void FUN_1800221e4(undefined8 *param_1);
longlong FUN_1800221f4(longlong param_1,longlong param_2);
undefined8 * FUN_180022238(undefined8 *param_1,uint param_2);
void FUN_180022274(longlong param_1,ulonglong *param_2);
void FUN_1800222d0(longlong param_1);
char * FUN_1800222f8(longlong param_1);
void FUN_18002230c(longlong *param_1,byte *param_2);
undefined8 * FUN_1800223d4(undefined8 *param_1,uint param_2);
undefined8 FUN_180022410(longlong param_1);
LPVOID FUN_18002244c(ulonglong param_1,ulonglong param_2);
LPVOID FUN_1800224cc(ulonglong param_1);
LPVOID FUN_180022548(LPVOID param_1,ulonglong param_2);
undefined8 FUN_1800225cc(PEXCEPTION_RECORD param_1,PVOID param_2,undefined8 param_3,longlong *param_4);
void FUN_1800227b0(void);
void FUN_1800227b8(PCONTEXT param_1);
void FUN_180022828(PCONTEXT param_1);
void FUN_18002289c(void);
void FUN_1800228b8(void);
void FUN_1800228d4(DWORD param_1);
void FUN_1800228f0(DWORD param_1,LPVOID param_2);
undefined8 FUN_18002290c(LPCRITICAL_SECTION param_1,DWORD param_2);
bool FUN_180022938(void);
void FUN_180022984(void);
void __stdcall Sleep(DWORD dwMilliseconds);
void FUN_180022d88(undefined4 param_1);
void FUN_180022da8(undefined8 param_1);
undefined8 FUN_180022dc8(int param_1);
bool FUN_180022e30(uint param_1,ulonglong param_2);
void FUN_180022eec(undefined8 param_1,uint param_2,undefined8 param_3,int param_4,uint param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9);
void FUN_180023014(ulonglong *param_1,ulonglong *param_2,ulonglong param_3,int param_4,uint param_5,int param_6);
void FUN_180023038(ulonglong *param_1,ulonglong *param_2,ulonglong param_3,int param_4,uint param_5,int param_6,longlong *param_7);
DWORD FUN_1800230b8(ulonglong *param_1,undefined1 *param_2,ulonglong param_3,uint param_4,int param_5,longlong *param_6);
ulonglong FUN_180023468(undefined1 *param_1,ulonglong param_2,int param_3,int param_4,int *param_5,char param_6,longlong *param_7);
void FUN_180023664(undefined8 *param_1,undefined1 *param_2,ulonglong param_3,int param_4,int param_5,longlong *param_6);
undefined4 FUN_18002375c(ulonglong *param_1,longlong param_2,int param_3,int *param_4,char param_5,longlong *param_6);
void FUN_1800238c0(undefined8 *param_1,ulonglong *param_2,longlong param_3,int param_4,longlong *param_5);
void FUN_180023994(undefined8 *param_1,ulonglong *param_2,ulonglong param_3,int param_4,int param_5,longlong *param_6);
void FUN_180023ad0(char *param_1,longlong *param_2);
void FUN_180023b70(int param_1,uint *param_2,byte *param_3,longlong *param_4);
void FUN_180023bb8(byte *param_1,longlong *param_2);
void FUN_180023c4c(void);
void FUN_180023c88(uint param_1,uint param_2);
void FUN_180023ca4(void);
void FUN_180023cfc(undefined8 param_1);
void FUN_180023d04(int param_1,undefined4 param_2,undefined4 param_3);
void FUN_180023df8(undefined8 param_1);
void FUN_180023e00(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4);
void FUN_180023e68(void);
void FUN_180023e88(void);
ulonglong FUN_180023ec4(undefined4 param_1,undefined **param_2);
void FUN_180024050(undefined **param_1,WCHAR *param_2,longlong *param_3,WCHAR *param_4);
void FUN_180024ae8(WCHAR param_1,undefined **param_2,int *param_3);
void FUN_180024b20(WCHAR param_1,int param_2,undefined **param_3,int *param_4);
void FUN_180024b74(WCHAR *param_1,int param_2,undefined **param_3,int *param_4,int *param_5);
void FUN_180024c10(int *param_1);
void FUN_180024c9c(LPVOID param_1);
int * FUN_180024e34(int *param_1);
int * FUN_180024ed8(void);
int * FUN_180024f50(undefined8 *param_1,int *param_2);
undefined8 FUN_180024fb4(void);
UINT FUN_180024fdc(UINT param_1);
void FUN_18002505c(longlong param_1);
void FUN_1800250ec(longlong param_1);
int * FUN_1800252d0(void);
int FUN_18002538c(UINT param_1);
void FUN_1800255d0(UINT param_1,longlong param_2);
ushort FUN_180025880(int param_1,ushort param_2,longlong *param_3);
void FUN_18002595c(LPVOID param_1);
void FUN_180025a90(LPVOID param_1);
DWORD * FUN_180025acc(void);
DWORD * FUN_180025af0(void);
void FUN_180025b74(longlong param_1,longlong param_2);
undefined8 FUN_180025c38(void);
void FUN_180025cb8(void);
void FUN_180025cdc(void);
undefined4 FUN_180025d24(int param_1,undefined8 param_2);
undefined4 FUN_180025ef0(int param_1,undefined8 param_2);
undefined8 FUN_180025f04(void);
void FUN_180026234(void);
undefined8 FUN_1800262a8(void);
void FUN_18002639c(byte *param_1,undefined8 *param_2,byte *param_3,int *param_4,int *param_5);
undefined8 FUN_180026564(void);
void FUN_180026698(void);
undefined8 FUN_180026744(void);
LPSTR FUN_18002674c(void);
void FUN_180026840(void);
void FUN_180026878(void);
void FUN_1800268b0(int param_1);
void FUN_1800268f4(void);
undefined8 FUN_18002697c(int param_1);
undefined4 FUN_180026a3c(void);
void FUN_180026aa0(int param_1);
longlong FUN_180026ac0(longlong param_1,ulonglong param_2);
ulonglong FUN_180026b10(longlong param_1);
bool FUN_180026b60(short *param_1);
void FUN_180026b90(void);
void FUN_180026bb0(void);
void FUN_180026bd0(void);
void FUN_180026be0(undefined8 param_1);
undefined8 FUN_180026c00(uint param_1);
void FUN_180026e34(undefined8 param_1);
char * FUN_180026e50(ulonglong *param_1);
DWORD FUN_180026ef8(short *param_1,longlong param_2,short *param_3);
DWORD FUN_180026f80(undefined2 *param_1,longlong param_2,short *param_3);
longlong FUN_180026fec(short *param_1);
DWORD FUN_180027008(short *param_1,longlong param_2,short *param_3,longlong param_4);
int FUN_1800270d4(int param_1);
void FUN_180027114(LPCWSTR param_1,undefined8 param_2,uint param_3);
DWORD FUN_180027388(undefined1 *param_1,longlong param_2,char *param_3);
ulonglong FUN_180027400(ulonglong *param_1,longlong param_2);
void FUN_180027468(longlong param_1);
void FUN_1800274f0(PVOID param_1,PVOID param_2);
void FUN_180027520(void);
void FUN_180027540(void);
void FUN_180027550(void);
void FUN_180027554(uint *param_1,ulonglong *param_2,ulonglong param_3,uint param_4,uint *param_5,uint *param_6);
void FUN_18002757c(uint *param_1,ulonglong *param_2,ulonglong param_3,uint param_4,uint *param_5,uint *param_6,int param_7);
void FUN_180027880(int param_1);
uint FUN_1800278b0(void);
uint FUN_1800278d0(uint param_1,uint param_2);
void FUN_18002794c(uint param_1);
uint FUN_18002796c(void);
ulonglong FUN_180027980(int param_1);
uint FUN_1800279fc(uint param_1,longlong *param_2);
uint FUN_180027b50(uint param_1);
DWORD FUN_180027b70(char *param_1,ulonglong param_2,int param_3,longlong param_4);
void FUN_180027c3c(uint *param_1,byte *param_2,longlong *param_3,undefined8 *param_4);
void FUN_180027d0c(uint *param_1,byte *param_2,longlong *param_3);
void FUN_180027dd4(uint *param_1,byte *param_2,longlong *param_3);
void FUN_180027ddc(uint *param_1,uint *param_2);
void FUN_180027eac(undefined8 param_1,int *param_2,undefined1 *param_3,longlong param_4);
undefined4 FUN_180027f70(longlong param_1);
undefined4 FUN_180027ffc(longlong param_1);
void FUN_180028030(longlong param_1,DWORD param_2,LPCWSTR param_3,int param_4,LPWSTR param_5,int param_6);
int FUN_1800280c0(longlong param_1,ushort *param_2,longlong param_3);
undefined8 FUN_180028118(void);
void FUN_1800281b0(void);
undefined ** FUN_1800281e0(void);
void FUN_1800281e8(ulonglong param_1);
void FUN_180028250(int param_1,longlong param_2);
void FUN_180028284(ulonglong param_1);
void FUN_1800282d4(int param_1,longlong param_2);
undefined4 FUN_1800282f4(longlong param_1);
byte FUN_18002831c(uint param_1);
undefined4 FUN_18002837c(uint param_1,WCHAR *param_2,uint param_3);
void FUN_180028460(uint param_1,WCHAR *param_2,ulonglong param_3);
undefined8 FUN_180028c54(uint param_1,LARGE_INTEGER param_2,DWORD param_3);
undefined8 FUN_180028d3c(uint param_1,LARGE_INTEGER param_2,DWORD param_3);
void FUN_180028dd0(undefined8 *param_1);
ushort FUN_180028e24(uint param_1,longlong *param_2);
ushort FUN_180028e68(uint param_1);
bool FUN_180028eb0(void);
void FUN_180028ec8(WCHAR param_1,undefined **param_2);
undefined4 FUN_1800290bc(LPWSTR param_1,byte *param_2,ulonglong param_3,longlong *param_4);
void FUN_180029210(LPWSTR param_1,byte *param_2,ulonglong param_3);
void FUN_180029218(longlong param_1);
void FUN_180029324(undefined8 *param_1);
void FUN_180029390(undefined8 *param_1);
void FUN_18002978c(longlong *param_1,longlong param_2,uint param_3,LPCSTR param_4,int param_5,undefined8 param_6,int param_7,UINT param_8,int param_9);
void FUN_180029a78(longlong *param_1,longlong param_2,uint param_3,LPCSTR param_4,int param_5,undefined8 param_6,int param_7,UINT param_8,int param_9);
void FUN_180029b10(longlong *param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,UINT param_6,int param_7);
void FUN_180029c88(longlong *param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,UINT param_6,int param_7);
DWORD FUN_180029d04(int *param_1,undefined1 (*param_2) [16],ulonglong param_3,WCHAR param_4,longlong *param_5);
void FUN_180029e90(int *param_1,undefined1 (*param_2) [16],ulonglong param_3,WCHAR param_4);
uint FUN_180029ea4(longlong *param_1,uint param_2,uint param_3,byte param_4);
void FUN_180029f20(uint param_1);
ulonglong FUN_180029f34(int *param_1);
undefined8 FUN_180029f80(int *param_1);
void FUN_180029ffc(void);
int FUN_18002a008(int param_1);
undefined4 FUN_18002a100(void);
void FUN_18002a110(undefined4 param_1);
void FUN_18002a11a(void);
void FUN_18002a150(ushort *param_1,uint *param_2);
void FUN_18002a708(ushort *param_1,uint *param_2);
void FUN_18002acc0(ushort *param_1,ushort *param_2,byte *param_3,int param_4,int param_5,int param_6,int param_7,longlong *param_8);
void FUN_18002b524(int *param_1,int param_2,uint param_3,short *param_4);
int FUN_18002bffc(void);
undefined8 FUN_18002c0a4(uint param_1);
undefined8 FUN_18002c13c(uint param_1);
undefined8 FUN_18002c1e8(uint param_1);
void FUN_18002c25c(uint param_1);
undefined2 FUN_18002c288(undefined2 param_1);
undefined2 FUN_18002c2e4(WCHAR param_1,undefined **param_2);
DWORD FUN_18002c474(uint param_1);
void FUN_18002c54c(char *param_1,int param_2,uint *param_3);
undefined4 FUN_18002c770(int *param_1);
undefined4 FUN_18002c7ec(int *param_1);
void FUN_18002c854(void);
void FUN_18002c874(void);
ulonglong FUN_18002c8b0(uint param_1);
undefined8 FUN_18002c974(uint param_1);
void FUN_18002ca30(undefined8 *param_1);
undefined4 * FUN_18002ca70(undefined4 *param_1);
void FUN_18002cb18(longlong param_1);
BOOL __stdcall IsProcessorFeaturePresent(DWORD ProcessorFeature);
void __stdcall RtlUnwindEx(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue,PCONTEXT ContextRecord,PUNWIND_HISTORY_TABLE HistoryTable);
void WTSQuerySessionInformationW(void);
void WTSFreeMemory(void);
void FUN_18002cb70(void);
void FUN_18002cb84(undefined8 param_1,longlong param_2);
void FUN_18002cbaa(undefined8 *param_1,longlong param_2);
void FUN_18002cbf3(undefined8 param_1,longlong param_2);
void FUN_18002cc17(void);
void FUN_18002cc30(void);
void FUN_18002cc49(void);
void FUN_18002cc62(void);
void FUN_18002cc7b(void);
void FUN_18002cc96(void);
bool FUN_18002ccc0(undefined8 *param_1);
void FUN_18002cce0(undefined8 param_1,longlong param_2);
void FUN_18002ccfe(void);
undefined8 FUN_18002cd17(undefined8 *param_1);
void FUN_18002cd43(undefined8 param_1,longlong param_2);
void FUN_18002cd5a(undefined8 param_1,longlong param_2);
void FUN_18002cd82(void);
void FUN_18002cd9b(void);
void FUN_18002cdb4(void);
void FUN_18002cdcd(undefined8 param_1,longlong param_2);
void FUN_18002cde5(undefined8 param_1,longlong param_2);

