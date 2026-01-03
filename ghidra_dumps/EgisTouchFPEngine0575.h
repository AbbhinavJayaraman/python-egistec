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

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    ImageBaseOffset32 action;
};

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    dword EndAddress; // Apply ImageBaseOffset32 to see reference
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct _s_IPToStateMapEntry _s_IPToStateMapEntry, *P_s_IPToStateMapEntry;

struct _s_IPToStateMapEntry {
    ImageBaseOffset32 Ip;
    __ehstate_t state;
};

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct _s_IPToStateMapEntry IPToStateMapEntry;

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    ImageBaseOffset32 dispUnwindMap;
    uint nTryBlocks;
    ImageBaseOffset32 dispTryBlockMap;
    uint nIPMapEntries;
    ImageBaseOffset32 dispIPToStateMap;
    int dispUnwindHelp;
    ImageBaseOffset32 dispESTypeList;
    int EHFlags;
};

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


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

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

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef ushort WORD;

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

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

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

typedef CHAR *PCSTR;

typedef CHAR *LPCSTR;

typedef LONG *PLONG;

typedef enum _SID_NAME_USE {
    SidTypeUser=1,
    SidTypeGroup=2,
    SidTypeDomain=3,
    SidTypeAlias=4,
    SidTypeWellKnownGroup=5,
    SidTypeDeletedAccount=6,
    SidTypeInvalid=7,
    SidTypeUnknown=8,
    SidTypeComputer=9,
    SidTypeLabel=10
} _SID_NAME_USE;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef CHAR *LPSTR;

typedef enum _SID_NAME_USE *PSID_NAME_USE;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS *PKNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_61 u;
    union _union_63 u2;
};

typedef EXCEPTION_ROUTINE *PEXCEPTION_ROUTINE;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

typedef PVOID PSID;

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
    char pdbpath[135];
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

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef WORD *LPWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef DWORD *PDWORD;

typedef BOOL *LPBOOL;

typedef struct HINSTANCE__ *HINSTANCE;

typedef HINSTANCE HMODULE;

typedef struct _FILETIME *PFILETIME;

typedef void *LPCVOID;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
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

typedef PVOID HDEVINFO;

typedef struct _SP_DEVICE_INTERFACE_DATA _SP_DEVICE_INTERFACE_DATA, *P_SP_DEVICE_INTERFACE_DATA;

struct _SP_DEVICE_INTERFACE_DATA {
    DWORD cbSize;
    GUID InterfaceClassGuid;
    DWORD Flags;
    ULONG_PTR Reserved;
};

typedef struct _SP_DEVICE_INTERFACE_DETAIL_DATA_A _SP_DEVICE_INTERFACE_DETAIL_DATA_A, *P_SP_DEVICE_INTERFACE_DETAIL_DATA_A;

struct _SP_DEVICE_INTERFACE_DETAIL_DATA_A {
    DWORD cbSize;
    CHAR DevicePath[1];
};

typedef struct _SP_DEVINFO_DATA _SP_DEVINFO_DATA, *P_SP_DEVINFO_DATA;

struct _SP_DEVINFO_DATA {
    DWORD cbSize;
    GUID ClassGuid;
    DWORD DevInst;
    ULONG_PTR Reserved;
};

typedef struct _SP_DEVICE_INTERFACE_DATA *PSP_DEVICE_INTERFACE_DATA;

typedef struct _SP_DEVICE_INTERFACE_DETAIL_DATA_A *PSP_DEVICE_INTERFACE_DETAIL_DATA_A;

typedef struct _SP_DEVINFO_DATA *PSP_DEVINFO_DATA;




void FUN_180001000(void);
bool FUN_180001020(PUCHAR param_1,ULONG param_2);
bool FUN_180001090(undefined8 *param_1,ULONG *param_2,uint param_3,PUCHAR param_4);
void FUN_1800011b0(undefined8 param_1,ULONG param_2,PUCHAR param_3);
bool FUN_1800011e0(PUCHAR param_1,ULONG param_2,undefined8 *param_3,ULONG *param_4,uint param_5,PUCHAR param_6,undefined8 *param_7);
bool FUN_1800012f0(PUCHAR param_1,ULONG param_2,undefined8 param_3,ULONG param_4,PUCHAR param_5);
NTSTATUS FUN_180001380(undefined8 *param_1,ULONG *param_2,undefined8 param_3,int *param_4,undefined8 param_5,PUCHAR param_6);
NTSTATUS FUN_1800014b0(undefined8 *param_1,ULONG *param_2,undefined8 param_3,int *param_4,undefined8 param_5,PUCHAR param_6);
NTSTATUS FUN_1800015d0(PUCHAR param_1,PUCHAR param_2,PVOID param_3,ULONG param_4,PUCHAR param_5,ULONG param_6);
bool FUN_180001790(undefined8 *param_1,undefined8 param_2,ULONG param_3,PUCHAR param_4);
bool FUN_180001820(undefined8 *param_1,undefined8 param_2,undefined8 param_3,PUCHAR param_4,undefined4 *param_5);
bool FUN_1800018e0(PUCHAR param_1);
bool FUN_1800019c0(PUCHAR param_1,int param_2);
undefined4 *FUN_180001ab0(uint param_1,uint param_2,undefined8 *param_3,undefined8 *param_4,undefined8 *param_5,uint *param_6);
undefined4 FUN_180001b70(longlong param_1);
void FUN_180001b80(HLOCAL param_1);
bool FUN_180001b90(int *param_1,ULONG param_2,PUCHAR param_3,ULONG param_4,PUCHAR param_5,ULONG param_6,ULONG *param_7);
bool FUN_180001d20(undefined8 *param_1,int param_2,undefined8 *param_3,int param_4,PVOID param_5,ULONG param_6,PUCHAR param_7,ULONG param_8);
bool FUN_180001e20(PUCHAR param_1,uint param_2,PUCHAR param_3,PUCHAR param_4,uint param_5,PUCHAR param_6,ULONG param_7,ULONG *param_8);
bool FUN_180001fd0(PUCHAR param_1,undefined8 param_2,PUCHAR param_3,PUCHAR param_4,uint param_5,PUCHAR param_6,ULONG param_7);
bool FUN_180002170(PUCHAR param_1,PUCHAR param_2,uint *param_3,uint *param_4,uint param_5);
bool thunk_FUN_180002170(PUCHAR param_1,PUCHAR param_2,uint *param_3,uint *param_4,uint param_5);
undefined8 FUN_1800023b0(PUCHAR param_1,undefined8 param_2,undefined8 param_3,undefined1 *param_4,undefined8 param_5,undefined8 *param_6);
UINT FUN_1800025c0(void);
undefined * FUN_180002870(void);
int FUN_1800028c0(int *param_1,int *param_2);
bool FUN_1800028e0(PUCHAR param_1,PUCHAR param_2,uint *param_3,uint *param_4,uint param_5,PUCHAR param_6,uint *param_7);
undefined8 FUN_180002bb0(int *param_1,uint *param_2,uint *param_3,uint *param_4,uint *param_5,longlong param_6);
undefined8 FUN_180002f90(undefined8 param_1,PUCHAR param_2);
void FUN_1800030d0(longlong param_1,uint *param_2,int param_3,undefined8 *param_4,longlong param_5);
void FUN_180003310(PUCHAR param_1,uint param_2,undefined8 *param_3,undefined8 *param_4,char *param_5);
void FUN_180003520(undefined8 *param_1,int *param_2,undefined8 param_3,char *param_4);
void FUN_1800036b0(undefined8 param_1,uint param_2);
void FUN_1800036d0(uint *param_1,uint param_2);
void FUN_180003870(longlong param_1,uint param_2,ulonglong *param_3,int param_4,longlong param_5);
void FUN_180003b00(undefined4 param_1);
void FUN_180003b20(void);
BOOL __stdcall InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount,DWORD Flags);
void FUN_180003b50(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 *param_4,int *param_5);
void FUN_180003e00(undefined8 *param_1,LPCSTR param_2,undefined8 param_3,int param_4,int param_5);
void FUN_180003ed0(longlong *param_1,LPCSTR param_2,UINT param_3);
void FUN_180003fe0(longlong *param_1,int param_2,LPVOID param_3);
void FUN_1800040a0(undefined8 param_1,uint *param_2,uint param_3);
void FUN_180004200(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void thunk_FUN_1800052c0(undefined8 *param_1,uint param_2,undefined8 param_3,undefined8 param_4);
undefined2 *thunk_FUN_180005360(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 thunk_FUN_180005510(char *param_1,undefined4 param_2,ulonglong param_3,undefined8 param_4);
undefined4 thunk_FUN_180005b10(undefined8 *param_1,int param_2,ulonglong param_3,uint **param_4,uint *param_5);
uint thunk_FUN_180006010(undefined8 *param_1,undefined8 *param_2,ulonglong param_3,ulonglong param_4,int *param_5);
undefined8 thunk_FUN_180006270(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 thunk_FUN_1800065e0(longlong *param_1,undefined8 param_2,ulonglong param_3,byte *param_4);
ulonglong thunk_FUN_180006a50(undefined8 *param_1,undefined8 param_2,undefined8 param_3,ulonglong param_4);
undefined8 FUN_180004390(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
LPVOID thunk_FUN_180006ed0(char *param_1,uint *param_2,ulonglong param_3,undefined *param_4);
undefined8 thunk_FUN_180007060(undefined8 *param_1,int param_2,ulonglong param_3,uint **param_4,uint *param_5,longlong param_6);
int FUN_180004410(undefined8 *param_1,uint param_2,int param_3,int *param_4,int *param_5,int param_6);
void FUN_180004540(longlong param_1,uint param_2,int param_3,int param_4,uint param_5);
void FUN_1800049b0(undefined8 param_1,longlong param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_180004a40(char *param_1,byte param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_180004ad0(longlong param_1,byte *param_2,undefined8 param_3,undefined8 param_4);
void FUN_180004b30(undefined8 *param_1,uint param_2,undefined8 param_3,undefined8 param_4);
void FUN_180004cc0(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_180004ec0(undefined8 *param_1,uint *param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_180005010(char *param_1,int *param_2,int param_3,undefined8 param_4);
void FUN_180005130(undefined8 param_1,int param_2,ulonglong param_3,ulonglong param_4);
undefined8 FUN_1800051e0(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_1800052c0(undefined8 *param_1,uint param_2,undefined8 param_3,undefined8 param_4);
undefined2 *FUN_180005360(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_180005510(char *param_1,undefined4 param_2,ulonglong param_3,undefined8 param_4);
uint FUN_180005980(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined4 FUN_180005b10(undefined8 *param_1,int param_2,ulonglong param_3,uint **param_4,uint *param_5);
uint FUN_180006010(undefined8 *param_1,undefined8 *param_2,ulonglong param_3,ulonglong param_4,int *param_5);
void FUN_180006190(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_180006270(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_1800063e0(int *param_1,longlong *param_2,int *param_3);
void FUN_1800064e0(longlong param_1,int param_2);
undefined8 FUN_1800065e0(longlong *param_1,undefined8 param_2,ulonglong param_3,byte *param_4);
uint FUN_1800067c0(int *param_1,uint *param_2,undefined4 *param_3,undefined8 param_4);
ulonglong FUN_180006a50(undefined8 *param_1,undefined8 param_2,undefined8 param_3,ulonglong param_4);
LPVOID FUN_180006ed0(char *param_1,uint *param_2,ulonglong param_3,undefined *param_4);
undefined8 FUN_180007060(undefined8 *param_1,int param_2,ulonglong param_3,uint **param_4,uint *param_5,longlong param_6);
uint FUN_1800072b0(undefined8 *param_1,undefined8 *param_2,ulonglong param_3,byte *param_4);
uint FUN_1800074a0(undefined8 *param_1,undefined8 *param_2,ulonglong param_3,undefined8 param_4);
ulonglong FUN_1800075e0(int *param_1,longlong *param_2,uint *param_3,byte *param_4);
LPVOID FUN_1800076f0(int param_1,int param_2);
void FUN_180007780(int param_1,int param_2,longlong param_3,int param_4);
void FUN_180007a30(int param_1,int param_2,longlong param_3,longlong param_4);
void FUN_180007d90(byte *param_1,int param_2,int param_3,undefined1 *param_4,undefined1 *param_5);
void FUN_180007f60(byte *param_1,int param_2,int param_3);
undefined8 FUN_1800080a0(byte *param_1,int param_2,int param_3,byte param_4,byte param_5);
void FUN_1800081d0(undefined8 *param_1,int param_2,int param_3,int *param_4,int *param_5);
ulonglong FUN_180008360(longlong param_1,int param_2,uint param_3,int param_4);
void FUN_180008400(undefined8 *param_1,uint param_2,uint param_3,int *param_4,int *param_5,undefined4 *param_6,int *param_7,int *param_8,uint *param_9);
int FUN_180008830(int param_1,int *param_2);
int FUN_180008c40(undefined8 *param_1,int param_2,int param_3,int *param_4,int *param_5,undefined *param_6,undefined *param_7);
void FUN_180008eb0(longlong param_1,undefined8 param_2,char param_3);
void FUN_180009050(longlong param_1,longlong *param_2,uint param_3,int param_4);
void FUN_180009290(byte *param_1,longlong *param_2,int param_3,undefined8 param_4,undefined8 param_5,int param_6);
void FUN_1800095c0(byte *param_1,longlong *param_2,int param_3,undefined8 param_4,undefined8 param_5,int param_6);
void FUN_180009900(byte *param_1,longlong param_2,uint param_3,ulonglong param_4);
void FUN_1800099e0(byte *param_1,longlong param_2,uint param_3,byte param_4);
void FUN_180009ad0(int *param_1,int param_2,int param_3);
ulonglong FUN_180009b20(int *param_1,int param_2);
int FUN_180009cd0(uint *param_1,int param_2,int param_3);
int FUN_180009f10(uint *param_1,int param_2);
void FUN_180009ff0(int *param_1,longlong param_2,int param_3,longlong param_4,int param_5,int param_6);
int * FUN_18000a0b0(int *param_1,int *param_2,int param_3,int *param_4);
void FUN_18000a1b0(int *param_1,short param_2);
void FUN_18000a3c0(longlong *param_1,ulonglong param_2,int param_3,int param_4,longlong param_5);
void FUN_18000a470(int param_1,int param_2,int *param_3,int *param_4,int param_5,int param_6,int param_7,int param_8,int param_9);
longlong FUN_18000a610(uint *param_1,int *param_2,char *param_3);
undefined8 FUN_18000a6c0(int *param_1,uint *param_2,undefined8 *param_3,int *param_4,int param_5,int param_6,char *param_7,longlong param_8);
int FUN_18000ab80(uint *param_1,uint *param_2,longlong param_3,undefined8 *param_4,int param_5,char *param_6,longlong *param_7);
int FUN_18000b7b0(uint *param_1,uint *param_2,longlong param_3,undefined8 *param_4);
void FUN_18000b870(int *param_1);
ulonglong FUN_18000b8c0(int *param_1,char *param_2);
int FUN_18000bad0(int *param_1,int *param_2,longlong param_3,longlong param_4,int param_5);
void FUN_18000bd40(int *param_1,short param_2);
LPVOID FUN_18000bf30(int param_1,int param_2);
LPVOID FUN_18000bfc0(void);
uint FUN_18000c0a0(int *param_1);
undefined8 FUN_18000c0f0(int *param_1,longlong param_2);
void FUN_18000c250(longlong param_1);
void FUN_18000c450(longlong param_1);
void FUN_18000c500(LPVOID param_1);
int * FUN_18000c570(LPVOID param_1);
int FUN_18000c730(longlong *param_1,longlong param_2,uint param_3);
void FUN_18000c7e0(int *param_1,int *param_2,int *param_3,int param_4,longlong param_5);
int * FUN_18000cab0(int *param_1,int param_2,longlong *param_3,longlong param_4,int param_5,int param_6,short param_7,int param_8,longlong param_9);
void FUN_18000cee0(longlong param_1,int param_2,int param_3,int *param_4,longlong param_5);
LPVOID FUN_18000d110(uint *param_1,uint *param_2,longlong param_3);
undefined8 FUN_18000d2c0(longlong param_1,longlong param_2);
int * FUN_18000d500(uint *param_1,longlong param_2);
int * FUN_18000d7d0(int *param_1,int *param_2,int *param_3,int param_4,longlong param_5);
undefined8 FUN_18000d880(int *param_1,int *param_2,longlong param_3);
int * FUN_18000ddc0(int *param_1,int *param_2,longlong param_3);
int FUN_18000de50(int *param_1);
int FUN_18000e0c0(int *param_1,int *param_2,undefined8 param_3,longlong param_4);
void FUN_18000e360(int *param_1,int *param_2,int *param_3);
void FUN_18000e4e0(void);
LPVOID FUN_18000e600(int param_1);
void FUN_18000e660(int *param_1,int *param_2);
int * FUN_18000e6f0(int *param_1,int param_2);
int * FUN_18000e7b0(int *param_1);
LPVOID FUN_18000e850(int param_1);
undefined8 FUN_18000e890(undefined4 *param_1,int param_2);
void FUN_18000e960(int *param_1);
void FUN_18000ea30(int *param_1);
int FUN_18000eab0(uint *param_1);
undefined8 FUN_18000eb20(uint *param_1,undefined2 *param_2);
undefined8 FUN_18000ebb0(uint *param_1,undefined1 *param_2,int param_3);
int FUN_18000ec70(uint *param_1,undefined2 *param_2);
int FUN_18000ed50(uint *param_1,char *param_2);
ulonglong FUN_18000efd0(int *param_1,short *param_2,int param_3);
int FUN_18000f0f0(int *param_1,undefined8 *param_2,int *param_3,longlong param_4);
int FUN_18000f280(uint *param_1,char *param_2);
int * FUN_18000f3c0(int param_1,int param_2);
void FUN_18000f460(longlong param_1,int param_2,int param_3,uint *param_4);
void FUN_18000f500(int *param_1);
void FUN_18000f5d0(longlong param_1,int param_2,int param_3,int *param_4);
int * FUN_18000f670(int *param_1);
void FUN_18000f6d0(uint *param_1,longlong param_2);
void FUN_18000fa80(int *param_1,longlong param_2,longlong param_3,int param_4);
void FUN_18000fc20(int *param_1,longlong param_2,longlong param_3);
void FUN_18000fde0(uint *param_1,longlong param_2,longlong param_3);
LPVOID FUN_18000ff90(int param_1,int param_2);
void FUN_180010020(int param_1,int param_2,longlong param_3);
void FUN_180010210(int param_1,int param_2,longlong param_3);
void FUN_1800103e0(uint param_1,int param_2,longlong param_3,undefined8 *param_4,undefined8 param_5,undefined8 param_6,longlong param_7);
uint FUN_180010b40(uint param_1,uint param_2);
void FUN_180010c00(int param_1,int param_2,longlong param_3,uint param_4,int param_5,longlong param_6,longlong param_7);
int FUN_1800115b0(int param_1,int param_2,longlong param_3,longlong param_4);
ulonglong FUN_180011740(longlong *param_1,int param_2,int param_3,longlong param_4);
void FUN_180011880(undefined8 *param_1,int param_2,int param_3);
longlong * FUN_180011900(longlong param_1,int param_2,int param_3,uint param_4,uint param_5);
undefined8 FUN_180011bc0(undefined8 *param_1,int param_2,int param_3);
ulonglong FUN_180011c60(longlong param_1,uint param_2,int param_3);
int FUN_180011e50(longlong param_1,int param_2,int param_3,undefined1 *param_4,int param_5);
void FUN_1800120b0(undefined8 *param_1,uint param_2,int param_3,longlong *param_4);
ulonglong FUN_1800122c0(longlong *param_1,uint param_2,uint param_3,longlong *param_4);
void FUN_180012820(longlong *param_1,int param_2,uint param_3);
void FUN_1800128f0(longlong *param_1,int param_2,int param_3);
void FUN_180012ce0(int param_1,int param_2,longlong param_3,int param_4);
void FUN_180012ef0(longlong *param_1,int param_2,int param_3);
int FUN_1800130c0(int param_1);
void FUN_180013600(undefined8 *param_1);
void FUN_180013690(ulonglong param_1,ulonglong param_2,uint param_3);
void FUN_1800137a0(int *param_1,uint param_2,int param_3,int param_4);
void FUN_180013fe0(int *param_1,int *param_2,longlong param_3,int param_4);
void FUN_180014160(int *param_1,longlong param_2,int param_3);
LPVOID FUN_180014250(int param_1,int param_2);
undefined8 FUN_1800142d0(int *param_1,int *param_2,uint param_3);
void FUN_180014750(longlong param_1,int *param_2);
void FUN_180014820(int *param_1,int *param_2,int param_3,int param_4,int param_5);
void FUN_180014960(int *param_1,int *param_2,int param_3,int param_4,int param_5);
void FUN_180014aa0(longlong *param_1,int *param_2);
undefined8 FUN_180014bd0(longlong *param_1,int *param_2);
int * FUN_180014d60(longlong param_1,longlong param_2);
undefined8 FUN_1800150b0(longlong param_1,int param_2,int param_3,int *param_4,int *param_5);
void FUN_1800151f0(int *param_1,longlong param_2);
int FUN_180015360(uint param_1,uint param_2);
void FUN_180015430(short *param_1,longlong *param_2,int param_3,longlong param_4,uint param_5,longlong param_6);
undefined8 FUN_180015770(longlong param_1,int param_2,int param_3,int param_4,int param_5,int param_6,undefined8 *param_7,longlong param_8);
void FUN_180015b70(longlong param_1,undefined8 *param_2,int param_3,int param_4,longlong param_5);
void FUN_180015d70(int *param_1,longlong *param_2,longlong param_3);
int * FUN_1800161b0(longlong *param_1,int *param_2);
undefined8 FUN_180016260(longlong *param_1,int param_2,uint param_3,undefined8 *param_4,int *param_5);
int FUN_180016510(longlong param_1,longlong param_2,uint param_3);
ulonglong FUN_180016680(uint *param_1);
undefined4 * FUN_180016850(void);
undefined8 FUN_1800168d0(void);
LPCRITICAL_SECTION FUN_1800168e0(LPCRITICAL_SECTION param_1,LPCWSTR param_2);
void FUN_180016a10(LPCRITICAL_SECTION param_1);
bool FUN_180016b00(longlong param_1,PUCHAR param_2,ULONG param_3,PUCHAR param_4,ULONG param_5,ULONG *param_6);
void FUN_180016bb0(longlong *param_1);
void FUN_180016c50(longlong *param_1,LPCWSTR param_2);
bool FUN_180016d10(longlong param_1);
void FUN_180017010(undefined8 *param_1,undefined8 param_2,undefined8 *param_3,int param_4,DWORD param_5);
undefined8 FUN_180017250(LPCRITICAL_SECTION param_1);
undefined8 FUN_180017260(undefined8 param_1,LPCWSTR param_2,LPCVOID param_3,DWORD param_4);
void FUN_1800172e0(LPCRITICAL_SECTION param_1);
undefined8 * FUN_180017430(undefined8 *param_1);
void FUN_180017450(undefined8 *param_1);
undefined8 * FUN_1800174a0(undefined8 *param_1,uint param_2);
void FUN_180017510(longlong param_1,longlong *param_2,int param_3,longlong *param_4,int param_5,undefined4 *param_6);
void FUN_180017940(longlong param_1,uint *param_2,uint *param_3,uint param_4);
void FUN_180017a50(longlong param_1,uint *param_2,uint *param_3,uint param_4);
void FUN_180017b60(longlong param_1,undefined8 param_2,undefined *param_3);
void FUN_180018000(longlong param_1,undefined8 *param_2,int param_3,undefined8 *param_4,int param_5);
void FUN_180018220(void);
DWORD FUN_180018230(void);
void FUN_180018310(uint param_1,longlong param_2,undefined8 param_3,undefined8 param_4);
void FUN_1800184c0(int param_1,LPCSTR param_2);
uint FUN_180018600(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_1800186d0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_180018770(longlong param_1,undefined4 *param_2,undefined8 *param_3,undefined8 param_4);
undefined8 FUN_1800187e0(longlong param_1,longlong param_2,longlong param_3,longlong param_4);
undefined8 FUN_180018820(longlong param_1,undefined8 param_2,longlong param_3,undefined8 param_4);
undefined8 FUN_180018890(longlong param_1,ulonglong *param_2,undefined8 param_3,undefined8 param_4);
uint FUN_180018910(undefined8 *param_1,longlong param_2,longlong param_3,ulonglong param_4,undefined4 *param_5);
uint FUN_180018b30(longlong param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4);
uint FUN_180018bd0(longlong param_1,byte param_2,longlong param_3,longlong param_4);
void FUN_180018cd0(longlong param_1,longlong param_2,ulonglong param_3,undefined8 **param_4,undefined8 **param_5,undefined8 *param_6,undefined8 *param_7,undefined8 *param_8,int *param_9);
void FUN_180019140(undefined8 *param_1,undefined8 *param_2,byte *param_3,int **param_4,longlong *param_5,undefined8 *param_6,undefined8 *param_7,int *param_8);
void FUN_1800198e0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined *param_4);
uint FUN_180019a70(longlong param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4);
ulonglong FUN_180019b20(longlong param_1,undefined8 *param_2,byte *param_3,LPDWORD param_4);
uint FUN_180019e00(longlong param_1,longlong param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5);
uint FUN_18001a040(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
uint FUN_18001a0a0(longlong param_1,undefined8 param_2,longlong param_3,undefined8 param_4,longlong param_5,undefined8 param_6,longlong param_7,longlong param_8);
undefined8 FUN_18001a110(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a130(longlong param_1,uint param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a1a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a1c0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a1f0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a220(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a250(longlong param_1,longlong param_2,ulonglong param_3,undefined8 param_4);
undefined8 FUN_18001a310(undefined8 param_1,undefined8 *param_2,undefined8 *param_3,undefined8 param_4);
undefined8 FUN_18001a370(longlong param_1,longlong param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a3e0(longlong param_1,longlong *param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a460(longlong param_1,undefined4 *param_2,ulonglong param_3,undefined8 param_4);
undefined8 FUN_18001a560(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a580(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a5a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001a5c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_18001a5e0(longlong *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_18001a910(undefined8 param_1,undefined8 *param_2,uint param_3);
BOOL FUN_18001aa60(HANDLE param_1,LPVOID param_2,DWORD param_3,LPVOID param_4,DWORD param_5,LPDWORD param_6);
void FUN_18001ab40(undefined8 param_1,longlong *param_2);
undefined8 FUN_18001ac10(void);
undefined8 WbioQueryEngineInterface(undefined8 *param_1);
undefined8 FUN_18001ac80(longlong param_1);
undefined8 FUN_18001acb0(longlong param_1);
undefined8 * FUN_18001ace0(undefined8 *param_1,LPCWSTR param_2,int param_3,int param_4);
undefined8 * FUN_18001ad60(LPCWSTR param_1);
void FUN_18001ae90(undefined8 *param_1);
char * FUN_18001aeb0(void);
char * FUN_18001aec0(void);
char * FUN_18001aed0(void);
char * FUN_18001aee0(void);
char * FUN_18001aef0(void);
undefined8 FUN_18001af00(void);
undefined8 FUN_18001af10(void);
undefined8 FUN_18001af20(void);
uint FUN_18001af30(uint *param_1,uint param_2);
undefined8 FUN_18001afe0(undefined8 *param_1,undefined8 *param_2);
void FUN_18001b060(HLOCAL param_1);
bool FUN_18001b0f0(undefined8 param_1,longlong param_2,longlong param_3,uint *param_4);
undefined8 FUN_18001b1a0(longlong param_1,int param_2,longlong *param_3);
bool FUN_18001b1d0(longlong param_1,undefined8 *param_2,uint *param_3);
undefined8 FUN_18001b240(longlong param_1,ushort param_2,longlong param_3);
uint FUN_18001b660(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_18001b700(void);
undefined1 FUN_18001b8a0(longlong param_1,undefined1 param_2);
ulonglong FUN_18001b980(longlong param_1,int param_2,undefined8 *param_3,uint *param_4);
undefined8 FUN_18001bdf0(longlong param_1);
DWORD FUN_18001be60(longlong param_1,short param_2,ushort param_3,undefined8 *param_4);
ulonglong FUN_18001bfb0(longlong param_1);
void FUN_18001c040(undefined1 *param_1,longlong param_2,undefined8 param_3,undefined8 param_4);
undefined8 * FUN_18001c070(undefined8 *param_1,int param_2,int param_3);
void FUN_18001c150(undefined8 *param_1);
undefined8 * FUN_18001c1c0(undefined8 *param_1,uint param_2);
undefined8 * FUN_18001c200(undefined8 *param_1,uint param_2);
void FUN_18001c230(longlong *param_1,undefined8 *param_2,ulonglong param_3,undefined8 param_4,byte param_5,undefined4 *param_6);
undefined8 FUN_18001c5b0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001c620(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001c670(longlong *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001c860(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001c8b0(longlong param_1,undefined8 *param_2,undefined4 *param_3,undefined8 param_4);
undefined4 FUN_18001c910(longlong param_1);
undefined8 FUN_18001c920(void);
undefined8 FUN_18001c930(void);
undefined8 FUN_18001c940(longlong *param_1,undefined8 param_2,LPCWSTR param_3,undefined8 param_4);
undefined8 FUN_18001caa0(longlong param_1,undefined8 *param_2,ulonglong param_3,undefined8 *param_4,uint param_5);
void FUN_18001caf0(char *param_1,HKEY param_2);
uint FUN_18001cd10(longlong param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_18001ced0(longlong param_1,ulonglong *param_2,ulonglong param_3,byte *param_4,uint param_5,undefined4 *param_6);
undefined4 * FUN_18001d0a8(undefined4 *param_1);
void FUN_18001d150(longlong param_1);
void thunk_FUN_18001d45c(LPVOID param_1);
undefined8 * FUN_18001d18c(undefined8 *param_1,longlong param_2);
void FUN_18001d1c0(ulonglong param_1);
undefined8 * FUN_18001d22c(undefined8 *param_1,uint param_2);
undefined4 FUN_18001d268(void);
PVOID FUN_18001d2ac(PVOID param_1);
int FUN_18001d3b8(PVOID param_1);
char * FUN_18001d3d0(ulonglong param_1,char param_2);
void FUN_18001d45c(LPVOID param_1);
undefined8 FUN_18001d49c(undefined8 param_1,ulonglong param_2,undefined8 param_3,longlong param_4);
void FUN_18001d4bc(ulonglong param_1,longlong param_2,uint *param_3);
void FUN_18001d530(longlong param_1);
undefined8 * FUN_18001d560(undefined8 *param_1,undefined8 *param_2,ulonglong param_3);
int FUN_18001dae0(ulonglong *param_1,longlong param_2,ulonglong param_3);
undefined1 (*) [16] FUN_18001dbc0(undefined1 (*param_1) [16],byte param_2,ulonglong param_3);
bool FUN_18001ddec(longlong param_1,longlong param_2);
undefined8 * FUN_18001de0c(undefined8 *param_1,uint param_2);
DWORD FUN_18001de48(undefined1 *param_1,longlong param_2,char *param_3);
DWORD FUN_18001deac(undefined2 *param_1,longlong param_2,short *param_3);
void FUN_18001df18(undefined1 *param_1,ulonglong param_2,longlong param_3,undefined8 param_4);
ulonglong FUN_18001df3c(undefined *param_1,undefined1 *param_2,ulonglong param_3,longlong param_4,undefined8 param_5,undefined8 param_6);
ulonglong FUN_18001e024(undefined1 *param_1,ulonglong param_2,longlong param_3,undefined8 param_4,undefined8 param_5);
void FUN_18001e094(undefined1 *param_1,ulonglong param_2,longlong param_3,undefined8 param_4);
uint FUN_18001e0ac(WCHAR *param_1,undefined8 *param_2,uint param_3,uint param_4);
void FUN_18001e294(WCHAR *param_1,undefined8 *param_2,uint param_3);
longlong * FUN_18001e29c(longlong *param_1,DWORD64 *param_2,longlong param_3,longlong *param_4);
longlong FUN_18001e368(undefined8 param_1,longlong param_2,undefined8 param_3,int param_4,uint *param_5,int *param_6,longlong *param_7);
void FUN_18001e494(longlong *param_1,DWORD64 *param_2,longlong param_3);
undefined8 FUN_18001e528(longlong *param_1,undefined8 param_2,longlong *param_3,ULONG_PTR param_4,DWORD64 *param_5,uint *param_6,undefined4 *param_7);
undefined4 FUN_18001e5cc(undefined4 *param_1,undefined8 param_2,undefined8 param_3);
undefined8 * FUN_18001e620(undefined8 *param_1,undefined8 param_2);
void FUN_18001e664(longlong param_1);
undefined8 FUN_18001e6c4(void);
undefined8 FUN_18001e6dc(void);
undefined4 FUN_18001e6f4(longlong param_1);
void FUN_18001e728(undefined8 param_1);
void FUN_18001e744(undefined8 param_1);
void FUN_18001e760(undefined8 *param_1,ULONG_PTR param_2,ULONG_PTR param_3,ULONG_PTR param_4,ULONG_PTR param_5,int param_6,ULONG_PTR param_7,undefined8 *param_8,byte param_9);
void FUN_18001e884(int *param_1,longlong param_2,ULONG_PTR param_3,DWORD64 *param_4);
void FUN_18001e920(void);
DWORD FUN_18001e970(char *param_1,longlong param_2,char *param_3);
void FUN_18001e9ec(void);
undefined8 FUN_18001ea18(undefined8 param_1,int param_2,longlong param_3);
void entry(undefined8 param_1,int param_2,longlong param_3,undefined8 param_4);
ulonglong FUN_18001ebb8(undefined8 param_1,int param_2,longlong param_3,undefined8 param_4);
LPVOID FUN_18001ecd8(LPVOID param_1,ulonglong param_2,ulonglong param_3);
LPVOID FUN_18001ed60(ulonglong param_1);
LPVOID FUN_18001ee18(ulonglong param_1,ulonglong param_2);
undefined8 * FUN_18001ee5c(undefined8 *param_1,undefined8 *param_2);
undefined8 * FUN_18001ee8c(undefined8 *param_1,undefined8 *param_2);
undefined8 * FUN_18001eea8(undefined8 *param_1,longlong param_2);
void FUN_18001eed4(undefined8 *param_1);
longlong FUN_18001eee4(longlong param_1,longlong param_2);
undefined8 * FUN_18001ef28(undefined8 *param_1,uint param_2);
void FUN_18001ef64(longlong param_1,ulonglong *param_2);
void FUN_18001efc0(longlong param_1);
char * FUN_18001efe8(longlong param_1);
undefined8 FUN_18001effc(undefined8 param_1);
void FUN_18001f030(undefined8 param_1);
void FUN_18001f038(longlong *param_1,byte *param_2);
void FUN_18001f100(uint param_1);
void FUN_18001f144(uint param_1);
void FUN_18001f15c(void);
void FUN_18001f2a4(int param_1);
void FUN_18001f2cc(void);
undefined8 FUN_18001f2dc(void);
void FUN_18001f374(UINT param_1);
void FUN_18001f380(void);
void FUN_18001f3cc(undefined8 *param_1,undefined8 *param_2);
void FUN_18001f42c(undefined8 *param_1,undefined8 *param_2);
void FUN_18001f468(void);
void FUN_18001f474(void);
void FUN_18001f480(UINT param_1,int param_2,int param_3);
undefined8 FUN_18001f618(longlong param_1);
LPVOID FUN_18001f654(ulonglong param_1,ulonglong param_2);
LPVOID FUN_18001f6d4(ulonglong param_1);
LPVOID FUN_18001f750(LPVOID param_1,ulonglong param_2);
undefined8 FUN_18001f7d4(PEXCEPTION_RECORD param_1,PVOID param_2,undefined8 param_3,longlong *param_4);
DWORD * FUN_18001f9b8(void);
void FUN_18001f9d8(DWORD param_1);
DWORD * FUN_18001fa28(void);
undefined4 FUN_18001fa48(int param_1);
bool FUN_18001fa98(void);
void FUN_18001fab8(void);
void FUN_18001fac4(undefined8 param_1);
void FUN_18001fb10(void);
undefined8 FUN_18001fbe4(void);
ulonglong FUN_18001fda0(ulonglong *param_1,longlong param_2);
void FUN_18001fe08(longlong param_1);
void FUN_18001fe74(int param_1,undefined4 param_2,undefined4 param_3);
void FUN_18001ff68(undefined8 param_1);
void FUN_18001ff70(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4);
void FUN_18001ffd8(void);
void FUN_18001fff8(void);
ulonglong FUN_180020034(undefined4 param_1,undefined **param_2);
longlong * FUN_1800201c0(longlong *param_1,longlong *param_2);
void FUN_180020268(undefined **param_1,byte *param_2,longlong *param_3,WCHAR *param_4);
void FUN_180020c90(byte param_1,undefined **param_2,int *param_3);
void FUN_180020cd8(byte param_1,int param_2,undefined **param_3,int *param_4);
void FUN_180020d2c(byte *param_1,int param_2,undefined **param_3,int *param_4,int *param_5);
ushort FUN_180020dc0(WCHAR param_1,ushort param_2);
int FUN_180020e28(ushort param_1);
void FUN_180020fc0(LPVOID param_1);
void FUN_1800210f4(LPVOID param_1);
DWORD * FUN_180021130(void);
DWORD * FUN_180021154(void);
void FUN_1800211d8(longlong param_1,longlong param_2);
undefined8 FUN_18002129c(void);
void FUN_18002131c(void);
void FUN_180021340(int *param_1);
undefined8 * FUN_1800213b0(undefined8 *param_1,longlong param_2);
undefined8 * FUN_1800213e4(undefined8 *param_1,uint param_2);
void FUN_180021420(ULONG_PTR param_1,longlong *param_2,ULONG_PTR param_3,DWORD64 *param_4,ULONG_PTR param_5,uint *param_6,byte *param_7,int *param_8);
void FUN_1800214e4(int *param_1,longlong *param_2,ULONG_PTR param_3,DWORD64 *param_4,uint *param_5,byte param_6,uint param_7);
void FUN_180021998(int *param_1,longlong *param_2,ULONG_PTR param_3,DWORD64 *param_4,ULONG_PTR param_5,int param_6,uint param_7);
undefined1 FUN_180021c00(longlong param_1,int *param_2);
longlong FUN_180021cd8(longlong param_1,int *param_2);
void FUN_180021cfc(longlong param_1,longlong *param_2,uint *param_3,byte *param_4);
char FUN_180021db4(longlong param_1,longlong *param_2,uint *param_3,byte *param_4);
undefined8 FUN_180022004(longlong param_1);
undefined8 FUN_180022208(undefined8 *param_1);
void FUN_18002225c(longlong *param_1,longlong *param_2,longlong param_3,int param_4);
undefined8 FUN_1800223f0(int *param_1,longlong *param_2,ULONG_PTR param_3,DWORD64 *param_4,uint *param_5,uint param_6,undefined8 param_7,byte param_8);
undefined8 FUN_180022614(byte *param_1,byte *param_2,byte *param_3);
void FUN_180022744(longlong *param_1,longlong *param_2,longlong param_3);
undefined4 FUN_18002276c(longlong *param_1,DWORD64 *param_2,longlong param_3);
void FUN_180022798(longlong *param_1,undefined8 param_2,longlong param_3,undefined4 param_4);
void FUN_1800227a4(longlong *param_1,DWORD64 *param_2,longlong param_3,int param_4);
void FUN_1800227e0(longlong param_1,longlong *param_2);
undefined4 FUN_1800227e8(longlong param_1,longlong param_2,longlong param_3);
void FUN_180022874(void);
void FUN_180022894(void);
void FUN_1800228b4(void);
void FUN_1800228d4(uint param_1,uint param_2);
void FUN_1800228f0(void);
void FUN_180022948(undefined8 param_1);
undefined4 FUN_180022950(int param_1,undefined8 param_2);
undefined4 FUN_180022b1c(int param_1,undefined8 param_2);
undefined8 FUN_180022b30(void);
void FUN_180022e60(void);
undefined8 FUN_180022ed4(void);
void FUN_180022fc8(byte *param_1,undefined8 *param_2,byte *param_3,int *param_4,int *param_5);
undefined8 FUN_180023190(void);
void FUN_1800232c4(void);
LPSTR FUN_180023370(void);
void FUN_180023464(PCONTEXT param_1);
void FUN_1800234d4(PCONTEXT param_1);
void FUN_180023548(void);
void FUN_180023564(void);
void FUN_180023580(void);
void FUN_18002359c(void);
undefined8 FUN_1800235b8(LPCRITICAL_SECTION param_1,DWORD param_2);
bool FUN_1800235e4(void);
void FUN_180023630(void);
void __stdcall Sleep(DWORD dwMilliseconds);
void FUN_180023a34(undefined4 param_1);
void FUN_180023a54(undefined8 param_1);
void FUN_180023a74(void);
void FUN_180023aac(void);
LPVOID FUN_180023ae4(LPVOID param_1,ulonglong param_2);
void FUN_180023bb8(void);
undefined * FUN_180023bfc(int param_1);
void FUN_180023c2c(int param_1);
LPVOID FUN_180023e9c(ulonglong param_1,ulonglong param_2,undefined4 *param_3);
char * FUN_180023f50(ulonglong *param_1);
void FUN_180023ff8(int param_1);
void FUN_18002403c(void);
undefined8 FUN_1800240c4(int param_1);
undefined4 FUN_180024184(void);
void FUN_1800241e8(int param_1);
longlong FUN_180024200(longlong param_1,ulonglong param_2);
ulonglong FUN_180024250(longlong param_1);
bool FUN_1800242a0(short *param_1);
void FUN_1800242d0(void);
void FUN_18002430c(void);
void FUN_18002431c(undefined8 param_1);
undefined8 FUN_18002433c(uint param_1);
void FUN_180024570(undefined8 param_1);
undefined8 FUN_180024578(void);
UINT FUN_1800245a0(UINT param_1);
void FUN_180024620(longlong param_1);
void FUN_1800246b0(longlong param_1);
int * FUN_180024894(void);
int FUN_180024950(UINT param_1);
void FUN_180024b94(UINT param_1,longlong param_2);
void FUN_180024e60(PVOID param_1,PVOID param_2);
void FUN_180024e90(void);
void FUN_180024eb0(void);
void FUN_180024ec0(void);
void FUN_180024ec4(void);
undefined8 FUN_180024ecc(void);
void FUN_180024f64(void);
undefined ** FUN_180024f94(void);
void FUN_180024f9c(ulonglong param_1);
void FUN_180025004(int param_1,longlong param_2);
void FUN_180025038(ulonglong param_1);
void FUN_180025088(int param_1,longlong param_2);
undefined4 FUN_1800250a8(longlong param_1);
byte FUN_1800250d0(uint param_1);
undefined4 FUN_180025130(uint param_1,WCHAR *param_2,uint param_3);
void FUN_180025214(uint param_1,WCHAR *param_2,ulonglong param_3);
undefined8 FUN_180025a08(uint param_1,LARGE_INTEGER param_2,DWORD param_3);
undefined8 FUN_180025af0(uint param_1,LARGE_INTEGER param_2,DWORD param_3);
void FUN_180025b84(undefined8 *param_1);
void FUN_180025bd8(int *param_1);
void FUN_180025c64(LPVOID param_1);
int * FUN_180025dfc(int *param_1);
int * FUN_180025ea0(void);
int * FUN_180025f18(undefined8 *param_1,int *param_2);
ushort FUN_180025f7c(uint param_1,longlong *param_2);
ushort FUN_180025fc0(uint param_1);
bool FUN_180026008(void);
DWORD FUN_180026020(int *param_1,undefined1 (*param_2) [16],ulonglong param_3,WCHAR param_4,longlong *param_5);
void FUN_1800261ac(int *param_1,undefined1 (*param_2) [16],ulonglong param_3,WCHAR param_4);
undefined4 FUN_1800261c0(LPWSTR param_1,byte *param_2,ulonglong param_3,longlong *param_4);
void FUN_180026314(LPWSTR param_1,byte *param_2,ulonglong param_3);
byte FUN_18002631c(longlong param_1);
void FUN_180026340(void);
undefined4 FUN_180026388(longlong param_1);
undefined4 FUN_180026414(longlong param_1);
void FUN_180026448(longlong param_1,DWORD param_2,LPCWSTR param_3,int param_4,LPWSTR param_5,int param_6);
int FUN_1800264d8(longlong param_1,ushort *param_2,longlong param_3);
uint FUN_180026530(longlong *param_1,uint param_2,uint param_3,byte param_4);
void FUN_1800265ac(uint param_1);
DWORD FUN_1800265c0(short *param_1,longlong param_2,short *param_3);
longlong FUN_180026648(short *param_1);
DWORD FUN_180026664(short *param_1,longlong param_2,short *param_3,longlong param_4);
int FUN_180026730(int param_1);
void FUN_180026770(LPCWSTR param_1,undefined8 param_2,uint param_3);
void FUN_1800269f0(longlong *param_1,longlong param_2,uint param_3,LPCSTR param_4,int param_5,undefined8 param_6,int param_7,UINT param_8,int param_9);
void FUN_180026cdc(longlong *param_1,longlong param_2,uint param_3,LPCSTR param_4,int param_5,undefined8 param_6,int param_7,UINT param_8,int param_9);
void FUN_180026d74(longlong *param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,UINT param_6,int param_7);
void FUN_180026eec(longlong *param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,UINT param_6,int param_7);
ulonglong FUN_180026f68(int *param_1);
undefined8 FUN_180026fb4(int *param_1);
void FUN_180027030(void);
int FUN_18002703c(int param_1);
int FUN_180027124(void);
undefined8 FUN_1800271cc(uint param_1);
undefined8 FUN_180027264(uint param_1);
undefined8 FUN_180027310(uint param_1);
void FUN_180027384(uint param_1);
undefined2 FUN_1800273b0(undefined2 param_1);
void FUN_18002740c(longlong param_1);
void FUN_180027518(undefined8 *param_1);
void FUN_180027584(undefined8 *param_1);
ushort FUN_180027980(int param_1,ushort param_2,longlong *param_3);
void FUN_180027a5c(void);
DWORD FUN_180027aa4(uint param_1);
undefined4 FUN_180027b7c(int *param_1);
undefined4 FUN_180027bf8(int *param_1);
void FUN_180027c60(void);
void FUN_180027c80(void);
void FUN_180027cbc(uint *param_1,byte *param_2,longlong *param_3,undefined8 *param_4);
void FUN_180027d8c(uint *param_1,byte *param_2,longlong *param_3);
void FUN_180027e54(uint *param_1,byte *param_2,longlong *param_3);
void thunk_FUN_180027e64(void);
void FUN_180027e64(void);
ulonglong FUN_180027eec(uint param_1);
undefined8 FUN_180027fb0(uint param_1);
void FUN_18002806c(undefined8 *param_1);
void FUN_1800280b0(ushort *param_1,uint *param_2);
void FUN_180028668(ushort *param_1,uint *param_2);
void FUN_180028c20(ushort *param_1,ushort *param_2,byte *param_3,int param_4,int param_5,int param_6,int param_7,longlong *param_8);
void FUN_180029484(ulonglong *param_1,ulonglong *param_2,ulonglong param_3,int param_4,uint param_5,int param_6);
void FUN_1800294a8(ulonglong *param_1,ulonglong *param_2,ulonglong param_3,int param_4,uint param_5,int param_6,longlong *param_7);
DWORD FUN_180029528(ulonglong *param_1,undefined1 *param_2,ulonglong param_3,uint param_4,int param_5,longlong *param_6);
ulonglong FUN_1800298d8(undefined1 *param_1,ulonglong param_2,int param_3,int param_4,int *param_5,char param_6,longlong *param_7);
void FUN_180029ad4(undefined8 *param_1,undefined1 *param_2,ulonglong param_3,int param_4,int param_5,longlong *param_6);
undefined4 FUN_180029bcc(ulonglong *param_1,longlong param_2,int param_3,int *param_4,char param_5,longlong *param_6);
void FUN_180029d30(undefined8 *param_1,ulonglong *param_2,longlong param_3,int param_4,longlong *param_5);
void FUN_180029e04(undefined8 *param_1,ulonglong *param_2,ulonglong param_3,int param_4,int param_5,longlong *param_6);
void FUN_180029f40(char *param_1,longlong *param_2);
void FUN_180029fe0(int param_1,uint *param_2,byte *param_3,longlong *param_4);
void FUN_18002a028(byte *param_1,longlong *param_2);
void FUN_18002a0bc(char *param_1,int param_2,uint *param_3);
ulonglong FUN_18002a2e0(int param_1);
uint FUN_18002a35c(uint param_1,longlong *param_2);
uint FUN_18002a4b0(uint param_1);
undefined1 (*) [16] FUN_18002a4d0(undefined1 (*param_1) [16],uint param_2);
DWORD FUN_18002a614(char *param_1,ulonglong param_2,int param_3,longlong param_4);
void FUN_18002a6e0(uint *param_1,uint *param_2);
void FUN_18002a7b0(undefined8 param_1,int *param_2,undefined1 *param_3,longlong param_4);
void FUN_18002a868(int *param_1,int param_2,uint param_3,short *param_4);
void __stdcall RtlUnwindEx(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue,PCONTEXT ContextRecord,PUNWIND_HISTORY_TABLE HistoryTable);
BOOL __stdcall IsProcessorFeaturePresent(DWORD ProcessorFeature);
void Unwind@18002b350(undefined8 param_1,longlong param_2);
void Unwind@18002b35c(undefined8 param_1,longlong param_2);
void Unwind@18002b368(undefined8 param_1,longlong param_2);
void Unwind@18002b374(undefined8 param_1,longlong param_2);
void FUN_18002b380(void);
void FUN_18002b394(longlong *param_1,longlong param_2);
void FUN_18002b3da(undefined8 param_1,longlong param_2);
void FUN_18002b400(undefined8 *param_1,longlong param_2);
void FUN_18002b449(undefined8 param_1,longlong param_2);
void FUN_18002b46d(void);
void FUN_18002b486(void);
void FUN_18002b49f(void);
undefined4 FUN_18002b4b8(undefined8 param_1,longlong param_2);
void FUN_18002b5ac(undefined8 param_1,longlong param_2);
bool FUN_18002b62a(undefined8 param_1,longlong param_2);
void FUN_18002b642(undefined8 *param_1);
void FUN_18002b658(void);
void FUN_18002b681(void);
void FUN_18002b69c(void);
bool FUN_18002b6c0(undefined8 *param_1);
void FUN_18002b6e0(undefined8 param_1,longlong param_2);
void FUN_18002b6fe(void);
void FUN_18002b717(undefined8 param_1,longlong param_2);
void FUN_18002b72e(void);
void FUN_18002b747(undefined8 param_1,longlong param_2);
void FUN_18002b76f(void);
void FUN_18002b788(void);
void FUN_18002b7a1(void);
void FUN_18002b7ba(undefined8 param_1,longlong param_2);
void FUN_18002b7d1(undefined8 param_1,longlong param_2);

