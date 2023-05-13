typedef unsigned char   undefined;

typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
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

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
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
    ImageBaseOffset32 pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef int __ehstate_t;

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

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

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

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

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

typedef unsigned short    wchar16;
typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    ImageBaseOffset32 EndAddress;
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct _s_IPToStateMapEntry _s_IPToStateMapEntry, *P_s_IPToStateMapEntry;

struct _s_IPToStateMapEntry {
    ImageBaseOffset32 Ip;
    __ehstate_t state;
};

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct _s_IPToStateMapEntry IPToStateMapEntry;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef struct _s_FuncInfo FuncInfo;

typedef ulonglong __uint64;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void * pVFTable;
    void * spare;
    char name[0];
};

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct DLGTEMPLATE DLGTEMPLATE, *PDLGTEMPLATE;

typedef ulong DWORD;

typedef ushort WORD;

struct DLGTEMPLATE {
    DWORD style;
    DWORD dwExtendedStyle;
    WORD cdit;
    short x;
    short y;
    short cx;
    short cy;
};

typedef struct DLGTEMPLATE * LPCDLGTEMPLATEW;

typedef longlong INT_PTR;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

typedef uint UINT;

typedef ulonglong UINT_PTR;

typedef UINT_PTR WPARAM;

typedef longlong LONG_PTR;

typedef LONG_PTR LPARAM;

typedef INT_PTR (* DLGPROC)(HWND, UINT, WPARAM, LPARAM);

struct HWND__ {
    int unused;
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo * LPCPINFO;

typedef struct tagLOGFONTW tagLOGFONTW, *PtagLOGFONTW;

typedef struct tagLOGFONTW LOGFONTW;

typedef long LONG;

typedef wchar_t WCHAR;

struct tagLOGFONTW {
    LONG lfHeight;
    LONG lfWidth;
    LONG lfEscapement;
    LONG lfOrientation;
    LONG lfWeight;
    BYTE lfItalic;
    BYTE lfUnderline;
    BYTE lfStrikeOut;
    BYTE lfCharSet;
    BYTE lfOutPrecision;
    BYTE lfClipPrecision;
    BYTE lfQuality;
    BYTE lfPitchAndFamily;
    WCHAR lfFaceName[32];
};

typedef struct GuardCfgTableEntry GuardCfgTableEntry, *PGuardCfgTableEntry;

struct GuardCfgTableEntry {
    ImageBaseOffset32 Offset;
    byte Pad[1];
};

typedef struct _TIME_ZONE_INFORMATION _TIME_ZONE_INFORMATION, *P_TIME_ZONE_INFORMATION;

typedef struct _TIME_ZONE_INFORMATION TIME_ZONE_INFORMATION;

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef struct _SYSTEMTIME SYSTEMTIME;

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

struct _TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulonglong ULONG_PTR;

typedef union _union_540 _union_540, *P_union_540;

typedef void * HANDLE;

typedef struct _struct_541 _struct_541, *P_struct_541;

typedef void * PVOID;

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

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef enum _FINDEX_INFO_LEVELS {
    FindExInfoStandard=0,
    FindExInfoBasic=1,
    FindExInfoMaxInfoLevel=2
} _FINDEX_INFO_LEVELS;

typedef struct _TIME_ZONE_INFORMATION * LPTIME_ZONE_INFORMATION;

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef WCHAR * LPWSTR;

typedef BYTE * LPBYTE;

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

typedef struct _STARTUPINFOW * LPSTARTUPINFOW;

typedef struct _WIN32_FIND_DATAW _WIN32_FIND_DATAW, *P_WIN32_FIND_DATAW;

typedef struct _WIN32_FIND_DATAW * LPWIN32_FIND_DATAW;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[260];
    WCHAR cAlternateFileName[14];
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _BY_HANDLE_FILE_INFORMATION _BY_HANDLE_FILE_INFORMATION, *P_BY_HANDLE_FILE_INFORMATION;

struct _BY_HANDLE_FILE_INFORMATION {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD dwVolumeSerialNumber;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD nNumberOfLinks;
    DWORD nFileIndexHigh;
    DWORD nFileIndexLow;
};

typedef enum _FINDEX_SEARCH_OPS {
    FindExSearchNameMatch=0,
    FindExSearchLimitToDirectories=1,
    FindExSearchLimitToDevices=2,
    FindExSearchMaxSearchOp=3
} _FINDEX_SEARCH_OPS;

typedef enum _FINDEX_SEARCH_OPS FINDEX_SEARCH_OPS;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef enum _FINDEX_INFO_LEVELS FINDEX_INFO_LEVELS;

typedef enum _GET_FILEEX_INFO_LEVELS {
    GetFileExInfoStandard=0,
    GetFileExMaxInfoLevel=1
} _GET_FILEEX_INFO_LEVELS;

typedef struct _BY_HANDLE_FILE_INFORMATION * LPBY_HANDLE_FILE_INFORMATION;

typedef enum _GET_FILEEX_INFO_LEVELS GET_FILEEX_INFO_LEVELS;

typedef struct _PROCESS_INFORMATION * LPPROCESS_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

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
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

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
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SYSTEMTIME * LPSYSTEMTIME;

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

typedef struct _struct_314 _struct_314, *P_struct_314;

struct _struct_314 {
    ULONGLONG Alignment;
    ULONGLONG Region;
};

typedef struct _struct_317 _struct_317, *P_struct_317;

struct _struct_317 {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:48;
    ULONGLONG HeaderType:1;
    ULONGLONG Reserved:3;
    ULONGLONG NextEntry:60;
};

typedef struct _struct_316 _struct_316, *P_struct_316;

struct _struct_316 {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:48;
    ULONGLONG HeaderType:1;
    ULONGLONG Init:1;
    ULONGLONG Reserved:2;
    ULONGLONG NextEntry:60;
};

typedef struct _struct_315 _struct_315, *P_struct_315;

struct _struct_315 {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:9;
    ULONGLONG NextEntry:39;
    ULONGLONG HeaderType:1;
    ULONGLONG Init:1;
    ULONGLONG Reserved:59;
    ULONGLONG Region:3;
};

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_238 _union_238, *P_union_238;

union _union_238 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_238 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef struct _RUNTIME_FUNCTION * PRUNTIME_FUNCTION;

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution=0,
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef struct _IMAGE_SECTION_HEADER * PIMAGE_SECTION_HEADER;

typedef WCHAR * PCNZWCH;

typedef union _SLIST_HEADER _SLIST_HEADER, *P_SLIST_HEADER;

union _SLIST_HEADER {
    struct _struct_314 s;
    struct _struct_315 Header8;
    struct _struct_316 Header16;
    struct _struct_317 HeaderX64;
};

typedef WCHAR * LPWCH;

typedef WCHAR * LPCWSTR;

typedef struct _M128A * PM128A;

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

typedef ulonglong * PDWORD64;

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

typedef struct _UNWIND_HISTORY_TABLE * PUNWIND_HISTORY_TABLE;

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

typedef union _SLIST_HEADER * PSLIST_HEADER;

typedef CHAR * LPSTR;

typedef CHAR * LPCSTR;

typedef void (* PFLS_CALLBACK_FUNCTION)(PVOID);

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser=1,
    TokenGroups=2,
    TokenPrivileges=3,
    TokenOwner=4,
    TokenPrimaryGroup=5,
    TokenDefaultDacl=6,
    TokenSource=7,
    TokenType=8,
    TokenImpersonationLevel=9,
    TokenStatistics=10,
    TokenRestrictedSids=11,
    TokenSessionId=12,
    TokenGroupsAndPrivileges=13,
    TokenSessionReference=14,
    TokenSandBoxInert=15,
    TokenAuditPolicy=16,
    TokenOrigin=17,
    TokenElevationType=18,
    TokenLinkedToken=19,
    TokenElevation=20,
    TokenHasRestrictions=21,
    TokenAccessInformation=22,
    TokenVirtualizationAllowed=23,
    TokenVirtualizationEnabled=24,
    TokenIntegrityLevel=25,
    TokenUIAccess=26,
    TokenMandatoryPolicy=27,
    TokenLogonSid=28,
    MaxTokenInfoClass=29
} _TOKEN_INFORMATION_CLASS;

typedef LARGE_INTEGER * PLARGE_INTEGER;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS * PKNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_61 u;
    union _union_63 u2;
};

typedef EXCEPTION_ROUTINE * PEXCEPTION_ROUTINE;

typedef DWORD LCID;

typedef enum _TOKEN_INFORMATION_CLASS TOKEN_INFORMATION_CLASS;

typedef HANDLE * PHANDLE;

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

typedef struct tm tm, *Ptm;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef ulong ULONG;

typedef struct HFONT__ HFONT__, *PHFONT__;

typedef struct HFONT__ * HFONT;

struct HFONT__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef DWORD * PDWORD;

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ * HMENU;

struct HMENU__ {
    int unused;
};

typedef struct _FILETIME * LPFILETIME;

typedef INT_PTR (* FARPROC)(void);

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef struct HDC__ * HDC;

typedef WORD * LPWORD;

typedef LONG_PTR LRESULT;

typedef struct tagRECT * LPRECT;

typedef BOOL * LPBOOL;

typedef struct HICON__ * HICON;

typedef void * HGDIOBJ;

typedef BYTE * PBYTE;

typedef void * LPCVOID;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
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

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

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
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer64 GuardAddressTakenIatEntryTable;
    qword GuardAddressTakenIatEntryCount;
    pointer64 GuardLongJumpTargetTable;
    qword GuardLongJumpTargetCount;
    pointer64 DynamicValueRelocTable;
    pointer64 CHPEMetadataPointer;
    pointer64 GuardRFFailureRoutine;
    pointer64 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer64 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    qword Reserved3;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
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

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
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

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef BOOL (* PHANDLER_ROUTINE)(DWORD);

typedef struct _CONSOLE_READCONSOLE_CONTROL _CONSOLE_READCONSOLE_CONTROL, *P_CONSOLE_READCONSOLE_CONTROL;

struct _CONSOLE_READCONSOLE_CONTROL {
    ULONG nLength;
    ULONG nInitialChars;
    ULONG dwCtrlWakeupMask;
    ULONG dwControlKeyState;
};

typedef struct _CONSOLE_READCONSOLE_CONTROL * PCONSOLE_READCONSOLE_CONTROL;

typedef int PMFN;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int pForwardCompat;
    int pCatchableTypeArray;
};

typedef struct _s_ThrowInfo ThrowInfo;

typedef char * va_list;

typedef ulonglong uintptr_t;

typedef struct __crt_multibyte_data __crt_multibyte_data, *P__crt_multibyte_data;

struct __crt_multibyte_data { // PlaceHolder Structure
};

typedef struct __acrt_ptd __acrt_ptd, *P__acrt_ptd;

struct __acrt_ptd { // PlaceHolder Structure
};

typedef struct __crt_locale_pointers __crt_locale_pointers, *P__crt_locale_pointers;

struct __crt_locale_pointers { // PlaceHolder Structure
};

typedef struct _xDISPATCHER_CONTEXT _xDISPATCHER_CONTEXT, *P_xDISPATCHER_CONTEXT;

struct _xDISPATCHER_CONTEXT { // PlaceHolder Structure
};

typedef struct <lambda_3e16ef9562a7dcce91392c22ab16ea36> <lambda_3e16ef9562a7dcce91392c22ab16ea36>, *P<lambda_3e16ef9562a7dcce91392c22ab16ea36>;

struct <lambda_3e16ef9562a7dcce91392c22ab16ea36> { // PlaceHolder Structure
};

typedef struct __crt_seh_guarded_call<void> __crt_seh_guarded_call<void>, *P__crt_seh_guarded_call<void>;

struct __crt_seh_guarded_call<void> { // PlaceHolder Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct _stat64i32 _stat64i32, *P_stat64i32;

struct _stat64i32 { // PlaceHolder Structure
};

typedef struct _wfinddata64i32_t _wfinddata64i32_t, *P_wfinddata64i32_t;

struct _wfinddata64i32_t { // PlaceHolder Structure
};

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct __acrt_stdio_stream_mode __acrt_stdio_stream_mode, *P__acrt_stdio_stream_mode;

struct __acrt_stdio_stream_mode { // PlaceHolder Structure
};

typedef struct __crt_locale_data __crt_locale_data, *P__crt_locale_data;

struct __crt_locale_data { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef struct <lambda_410d79af7f07d98d83a3f525b3859a53> <lambda_410d79af7f07d98d83a3f525b3859a53>, *P<lambda_410d79af7f07d98d83a3f525b3859a53>;

struct <lambda_410d79af7f07d98d83a3f525b3859a53> { // PlaceHolder Structure
};


// WARNING! conflicting data type names: /Demangler/wchar_t - /wchar_t

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry { // PlaceHolder Structure
};

typedef struct __crt_deferred_errno_cache __crt_deferred_errno_cache, *P__crt_deferred_errno_cache;

struct __crt_deferred_errno_cache { // PlaceHolder Structure
};

typedef struct <lambda_38119f0e861e05405d8a144b9b982f0a> <lambda_38119f0e861e05405d8a144b9b982f0a>, *P<lambda_38119f0e861e05405d8a144b9b982f0a>;

struct <lambda_38119f0e861e05405d8a144b9b982f0a> { // PlaceHolder Structure
};

typedef enum __acrt_rounding_mode {
} __acrt_rounding_mode;

typedef struct void_(__cdecl**___ptr64)(int) void_(__cdecl**___ptr64)(int), *Pvoid_(__cdecl**___ptr64)(int);

struct void_(__cdecl**___ptr64)(int) { // PlaceHolder Structure
};

typedef struct __crt_stdio_stream __crt_stdio_stream, *P__crt_stdio_stream;

struct __crt_stdio_stream { // PlaceHolder Structure
};

typedef enum date_type {
} date_type;

typedef enum length_modifier {
} length_modifier;

typedef struct string_output_adapter<wchar_t> string_output_adapter<wchar_t>, *Pstring_output_adapter<wchar_t>;

struct string_output_adapter<wchar_t> { // PlaceHolder Structure
};

typedef struct string_output_adapter<char> string_output_adapter<char>, *Pstring_output_adapter<char>;

struct string_output_adapter<char> { // PlaceHolder Structure
};

typedef struct argument_list<wchar_t> argument_list<wchar_t>, *Pargument_list<wchar_t>;

struct argument_list<wchar_t> { // PlaceHolder Structure
};

typedef enum transition_type {
} transition_type;

typedef struct write_result write_result, *Pwrite_result;

struct write_result { // PlaceHolder Structure
};

typedef struct file_options file_options, *Pfile_options;

struct file_options { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef struct lconv lconv, *Plconv;

struct lconv {
    char * decimal_point;
    char * thousands_sep;
    char * grouping;
    char * int_curr_symbol;
    char * currency_symbol;
    char * mon_decimal_point;
    char * mon_thousands_sep;
    char * mon_grouping;
    char * positive_sign;
    char * negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t * _W_decimal_point;
    wchar_t * _W_thousands_sep;
    wchar_t * _W_int_curr_symbol;
    wchar_t * _W_currency_symbol;
    wchar_t * _W_mon_decimal_point;
    wchar_t * _W_mon_thousands_sep;
    wchar_t * _W_positive_sign;
    wchar_t * _W_negative_sign;
};

typedef ushort wint_t;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct * pthreadlocinfo;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

struct localerefcount {
    char * locale;
    wchar_t * wlocale;
    int * refcount;
    int * wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int * lconv_intl_refcount;
    int * lconv_num_refcount;
    int * lconv_mon_refcount;
    struct lconv * lconv;
    int * ctype1_refcount;
    ushort * ctype1;
    ushort * pctype;
    uchar * pclmap;
    uchar * pcumap;
    struct __lc_time_data * lc_time_curr;
    wchar_t * locale_name[6];
};

struct __lc_time_data {
    char * wday_abbr[7];
    char * wday[7];
    char * month_abbr[12];
    char * month[12];
    char * ampm[2];
    char * ww_sdatefmt;
    char * ww_ldatefmt;
    char * ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t * _W_wday_abbr[7];
    wchar_t * _W_wday[7];
    wchar_t * _W_month_abbr[12];
    wchar_t * _W_month[12];
    wchar_t * _W_ampm[2];
    wchar_t * _W_ww_sdatefmt;
    wchar_t * _W_ww_ldatefmt;
    wchar_t * _W_ww_timefmt;
    wchar_t * _W_ww_locale_name;
};

typedef ulonglong size_t;

typedef int errno_t;

typedef size_t rsize_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct * pthreadmbcinfo;

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t * mblocalename;
};

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef ushort wctype_t;

typedef struct localeinfo_struct * _locale_t;




void FUN_140001000(undefined8 param_1,undefined8 param_2,undefined8 param_3,FILE **param_4);
undefined * FUN_140001040(void);
uint FUN_140001050(FILE **param_1,longlong param_2,FILE *param_3,undefined (*param_4) [32]);
undefined (*) [32]FUN_1400012b0(FILE **param_1,longlong param_2,undefined8 param_3,undefined8 param_4);
ulonglong FUN_140001440(FILE **param_1,longlong param_2,size_t param_3,undefined8 param_4);
int * FUN_140001650(longlong param_1,longlong param_2);
char * FUN_1400016d0(longlong param_1,char *param_2,size_t param_3,undefined8 param_4);
ulonglong FUN_140001780(longlong param_1,int *param_2,undefined8 param_3,undefined8 param_4);
void FUN_1400017b0(FILE **param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_1400019d0(FILE **param_1,undefined8 param_2,undefined8 param_3);
void FUN_140001ab0(FILE **param_1);
LPVOID FUN_140001af0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
int FUN_140001b30(undefined *param_1,ulonglong param_2,ulonglong param_3,undefined8 param_4);
void FUN_140001b90(HINSTANCE *param_1);
undefined8 FUN_140001f70(HWND param_1,int param_2,ushort param_3,HINSTANCE *param_4);
void FUN_140002030(longlong param_1,uint param_2,short param_3);
void FUN_140002240(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,undefined8 param_4);
undefined4 FUN_1400023b0(LPCSTR param_1,LPCSTR param_2,LPCSTR param_3,undefined8 param_4);
int FUN_140002470(undefined2 *param_1,ulonglong param_2,longlong param_3,undefined8 param_4);
void FUN_1400024d0(undefined8 param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4);
void FUN_140002620(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_140002770(ulonglong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_140002880(ulonglong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_140002990(ulonglong *param_1,undefined8 param_2);
char * FUN_140002de0(void);
void FUN_140002ff0(char *param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_140003090(FILE **param_1,undefined8 param_2,longlong param_3,FILE **param_4);
void FUN_1400030f0(FILE **param_1,undefined *param_2,size_t param_3,undefined8 param_4);
void thunk_FUN_1400046a0(longlong param_1);
void _guard_check_icall(void);
undefined8 FUN_140003260(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_140003a50(longlong param_1,char *param_2);
undefined8 FUN_140003aa0(longlong param_1,undefined (*param_2) [16]);
undefined8 FUN_140003b00(undefined (*param_1) [16],undefined8 param_2);
void FUN_140003b80(LPSTR param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_140003c20(LPCSTR param_1);
void FUN_140003c90(LPCSTR param_1,LPCSTR param_2);
char * FUN_140003d10(char *param_1,undefined8 param_2,char *param_3);
undefined8 FUN_140003dd0(HMODULE param_1,int param_2,undefined8 param_3,undefined8 param_4);
void FUN_1400046a0(longlong param_1);
undefined8 FUN_1400046c0(FILE **param_1);
undefined8 FUN_140004820(longlong param_1,undefined8 param_2,longlong param_3,char *param_4);
void FUN_140004940(longlong param_1);
void FUN_140004aa0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_140004cc0(longlong param_1,undefined8 param_2,undefined8 param_3,LPWSTR *param_4);
undefined8 FUN_140004f50(void);
undefined8 FUN_140004f90(longlong param_1);
undefined8 FUN_140005010(longlong *param_1);
undefined8 FUN_1400053c0(void);
undefined8 FUN_1400053d0(void);
void FUN_1400053e0(longlong param_1);
undefined4 FUN_1400054c0(undefined8 param_1,undefined8 param_2,int param_3,longlong param_4);
undefined8 FUN_1400055b0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_140005620(FILE **param_1,longlong param_2,char *param_3,undefined8 param_4);
undefined8 FUN_140005870(longlong *param_1);
undefined4 FUN_1400059a0(undefined *param_1,int param_2,undefined *param_3,undefined *param_4);
undefined8 FUN_140005ac0(longlong param_1,FILE **param_2,undefined (*param_3) [32],undefined8 param_4);
undefined8 FUN_140005c70(longlong *param_1);
void FUN_140005da0(LPVOID *param_1);
LPVOID FUN_140005e20(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined4 FUN_140005e60(undefined *param_1,undefined *param_2);
void FUN_140006440(LPCSTR param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_1400065c0(LPCSTR param_1,undefined8 param_2,undefined8 param_3);
undefined8 FUN_1400066e0(longlong param_1,undefined8 param_2,size_t param_3,undefined8 param_4);
void FUN_140006740(LPSTR param_1,LPCSTR param_2,undefined8 param_3,undefined8 param_4);
void FUN_140006950(LPCSTR param_1);
void FUN_140006a00(undefined8 param_1,undefined8 param_2);
void FUN_140006bf0(LPCSTR param_1);
errno_t FUN_140006e80(LPCSTR param_1,LPCSTR param_2);
BOOL FUN_140006ef0(LPCSTR param_1);
void FUN_140006f30(LPCSTR param_1);
bool FUN_1400070f0(HMODULE param_1);
HMODULE FUN_140007110(LPCSTR param_1);
longlong FUN_140007160(FILE *param_1,void *param_2,ulonglong param_3);
void FUN_140007290(LPCWSTR param_1,longlong param_2,undefined4 *param_3);
void FUN_140007410(DWORD param_1);
int FUN_140007500(undefined2 *param_1,ulonglong param_2,longlong param_3,undefined8 param_4);
LPSTR * FUN_140007560(int param_1,longlong param_2);
bool FUN_140007700(wint_t *param_1);
void FUN_140007780(LPCWSTR param_1);
void FUN_140007800(LPCWSTR param_1);
LPWSTR FUN_140007990(LPWSTR param_1,LPCSTR param_2,int param_3);
LPSTR FUN_140007aa0(LPSTR param_1,LPCWSTR param_2,int param_3);
LPWSTR * FUN_140007b90(int param_1,longlong param_2);
int FUN_140007d10(undefined (**param_1) [32],int param_2);
undefined8 FUN_140009590(longlong param_1);
int FUN_1400098a0(longlong param_1,char *param_2,int param_3);
undefined4 FUN_1400098b0(longlong param_1,longlong param_2,ulonglong param_3);
uint FUN_1400099c0(uint param_1,byte *param_2,uint param_3);
uint FUN_140009cb0(uint param_1,uint *param_2,uint param_3);
void FUN_14000a170(undefined8 param_1,int param_2,int param_3);
void FUN_14000a180(undefined8 param_1,LPVOID param_2);
void FUN_14000a190(int param_1,ushort *param_2,uint param_3,longlong *param_4,uint *param_5,undefined *param_6);
void FUN_14000a730(byte **param_1,int param_2);
void ConvertSidToStringSidW(void);
void ConvertStringSecurityDescriptorToSecurityDescriptorW(void);
void __GSHandlerCheckCommon(ulonglong param_1,longlong param_2,uint *param_3);
void FUN_14000acc0(longlong param_1);
void __chkstk(void);
void FUN_14000ad40(void);
undefined8 FUN_14000ae00(void);
uint FUN_14000ae10(void);
ulonglong entry(void);
void __raise_securityfailure(_EXCEPTION_POINTERS *param_1);
void FUN_14000aff0(void);
void FUN_14000b0c4(void);
void FUN_14000b0d8(undefined4 param_1);
void capture_current_context(PCONTEXT param_1);
void capture_previous_context(PCONTEXT param_1);
ulonglong __scrt_acquire_startup_lock(void);
ulonglong __scrt_initialize_crt(int param_1);
undefined8 __scrt_initialize_onexit_tables(uint param_1);
ulonglong __scrt_is_nonwritable_in_current_image(longlong param_1);
void __scrt_release_startup_lock(char param_1);
undefined8 __scrt_uninitialize_crt(bool param_1,char param_2);
_onexit_t _onexit(_onexit_t _Func);
int atexit(void *param_1);
void __security_init_cookie(void);
undefined8 FUN_14000b55c(void);
undefined8 FUN_14000b564(void);
void FUN_14000b56c(void);
undefined FUN_14000b580(void);
undefined * FUN_14000b584(void);
void FUN_14000b58c(void);
bool FUN_14000b5a8(void);
undefined * FUN_14000b5b4(void);
undefined * FUN_14000b5bc(void);
void FUN_14000b5c4(void);
void FUN_14000b5cc(undefined4 param_1);
WORD __scrt_get_show_window_mode(void);
undefined8 thunk_FUN_1400053c0(void);
ulonglong FUN_14000b75c(void);
void FUN_14000b7b0(void);
undefined8 __scrt_unhandled_exception_filter(int **param_1);
void FUN_14000b81c(void);
void FUN_14000b860(void);
undefined8 FUN_14000b89c(void);
bool __scrt_is_ucrt_dll_in_use(void);
undefined (*) [32]FUN_14000ba90(undefined (*param_1) [32],undefined (*param_2) [32],ulonglong param_3);
undefined (*) [32] FUN_14000c140(undefined (*param_1) [32],byte param_2,ulonglong param_3);
char * strchr(char *_Str,int _Val);
undefined (*) [16] FUN_14000c548(undefined (*param_1) [16],uint param_2);
wchar_t * wcschr(wchar_t *_Str,wchar_t _Ch);
int memcmp(void *_Buf1,void *_Buf2,size_t _Size);
undefined8 FUN_14000c7d8(PEXCEPTION_RECORD param_1,PVOID param_2,longlong param_3,longlong *param_4);
ulonglong __vcrt_initialize(void);
undefined8 __vcrt_uninitialize(char param_1);
uint __std_type_info_compare(longlong param_1,longlong param_2);
void __DestructExceptionObject(int *param_1);
void FUN_14000cab0(undefined8 param_1,undefined *UNRECOVERED_JUMPTABLE);
undefined4 _IsExceptionObjectToBeDestroyed(longlong param_1);
longlong __AdjustPointer(longlong param_1,int *param_2);
undefined8 __FrameUnwindFilter(int **param_1);
longlong __current_exception(void);
longlong __current_exception_context(void);
void Unwind@14000cb98(void);
void FUN_14000cbc0(void);
void FUN_14000cbf0(void);
void __except_validate_context_record(longlong param_1);
void FUN_14000cc30(undefined *param_1);
void __vcrt_getptd(void);
LPVOID __vcrt_getptd_noexit(void);
uint __vcrt_initialize_ptd(void);
undefined __vcrt_uninitialize_ptd(void);
undefined8 __vcrt_initialize_locks(void);
undefined8 __vcrt_uninitialize_locks(void);
FARPROC FUN_14000ce18(uint param_1,LPCSTR param_2,uint *param_3,uint *param_4);
void __vcrt_FlsAlloc(void);
void __vcrt_FlsFree(DWORD param_1);
void __vcrt_FlsGetValue(DWORD param_1);
void __vcrt_FlsSetValue(DWORD param_1,LPVOID param_2);
void __vcrt_InitializeCriticalSectionEx(LPCRITICAL_SECTION param_1,DWORD param_2);
undefined4 _CallSETranslator<>(void);
longlong FUN_14000d14c(longlong param_1,int param_2);
ulonglong FUN_14000d1b0(ulonglong *param_1,longlong param_2);
void __FrameHandler3::FrameUnwindToEmptyState(__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3);
longlong * FUN_14000d240(longlong *param_1,ulonglong *param_2,longlong param_3,longlong *param_4);
undefined4 *FUN_14000d30c(undefined4 *param_1,undefined8 param_2,int param_3,ulonglong *param_4,longlong param_5);
void __FrameHandler3::UnwindNestedFrames(__uint64 *param_1,EHExceptionRecord *param_2,_CONTEXT *param_3,__uint64 *param_4,void *param_5,_s_FuncInfo *param_6,int param_7,int param_8,_s_HandlerType *param_9,_xDISPATCHER_CONTEXT *param_10,uchar param_11);
undefined8 * _CreateFrameInfo(undefined8 *param_1,undefined8 param_2);
void _FindAndUnlinkFrame(longlong param_1);
undefined8 _GetImageBase(void);
undefined8 _GetThrowImageBase(void);
void FUN_14000d608(undefined8 param_1);
void FUN_14000d620(undefined8 param_1);
void FUN_14000d638(int *param_1,__uint64 param_2,_CONTEXT *param_3,ulonglong *param_4);
void FUN_14000d6c0(longlong *param_1,ulonglong *param_2,longlong param_3);
int __FrameHandler3::GetUnwindTryBlock(__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3);
void __FrameHandler3::SetState(__uint64 *param_1,_s_FuncInfo *param_2,int param_3);
void __FrameHandler3::SetUnwindTryBlock(__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3,int param_4);
void FUN_14000d75c(longlong param_1,ulonglong *param_2);
ulonglong FUN_14000d764(longlong param_1,longlong param_2,ulonglong param_3);
ulonglong FUN_14000d7cc(longlong param_1,undefined (*param_2) [32],int *param_3,byte *param_4);
void BuildCatchObjectInternal<class___FrameHandler3>(EHExceptionRecord *param_1,void *param_2,_s_HandlerType *param_3,_s_CatchableType *param_4);
void CatchIt<class___FrameHandler3>(EHExceptionRecord *param_1,__uint64 *param_2,_CONTEXT *param_3,_xDISPATCHER_CONTEXT *param_4,_s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,_s_TryBlockMapEntry *param_8,int param_9,__uint64 *param_10,uchar param_11,uchar param_12);
void FUN_14000db60(int *param_1,__uint64 *param_2,_CONTEXT *param_3,ulonglong *param_4,_s_FuncInfo *param_5,uchar param_6,int param_7,__uint64 *param_8);
void FUN_14000e038(int *param_1,__uint64 *param_2,_CONTEXT *param_3,ulonglong *param_4,_s_FuncInfo *param_5,int param_6,int param_7,__uint64 *param_8);
int TypeMatchHelper<class___FrameHandler3>(_s_HandlerType *param_1,_s_CatchableType *param_2,_s_ThrowInfo *param_3);
undefined8 FUN_14000e394(int *param_1,__uint64 *param_2,_CONTEXT *param_3,ulonglong *param_4,_s_FuncInfo *param_5,int param_6,__uint64 *param_7,uchar param_8);
undefined8 * FUN_14000e5cc(undefined8 *param_1,longlong param_2);
undefined8 * FUN_14000e608(undefined8 *param_1);
exception * __thiscall std::exception::exception(exception *this,exception *param_1);
undefined8 * FUN_14000e670(undefined8 *param_1,uint param_2);
void * __FrameHandler3::CxxCallCatchBlock(_EXCEPTION_RECORD *param_1);
int ExFilterRethrow(_EXCEPTION_POINTERS *param_1,EHExceptionRecord *param_2,int *param_3);
void FUN_14000e934(__uint64 *param_1,ulonglong *param_2,_s_FuncInfo *param_3,int param_4);
int __FrameHandler3::GetHandlerSearchState(__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3);
ulonglong FUN_14000eb58(longlong param_1,int *param_2);
uchar Is_bad_exception_allowed(_s_ESTypeList *param_1);
void FUN_14000ecd0(undefined8 param_1,undefined *UNRECOVERED_JUMPTABLE,undefined8 param_3);
void _CallMemberFunction2(void *param_1,void *param_2,void *param_3,int param_4);
char * FUN_14000ecf0(longlong param_1);
void _CallSettingFrame(void);
void FUN_14000eda0(void);
void __std_exception_copy(char **param_1,char **param_2);
void __std_exception_destroy(LPVOID *param_1);
void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo);
undefined FUN_14000ef70(void);
undefined * FUN_14000ef98(void);
undefined8 * FUN_14000efa0(void);
ulonglong FUN_14000efa8(FILE *param_1,__acrt_ptd **param_2);
ulonglong FUN_14000f024(FILE *param_1,__acrt_ptd **param_2);
__acrt_ptd * FUN_14000f0c8(__acrt_ptd **param_1);
ulonglong FUN_14000f130(FILE *param_1);
ulonglong FUN_14000f1c8(FILE *param_1);
int feof(FILE *_File);
int ferror(FILE *_File);
size_t _fread_nolock_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File);
size_t fread(void *_DstBuf,size_t _ElementSize,size_t _Count,FILE *_File);
size_t fread_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File);
ulonglong FUN_14000f5e0(FILE *param_1,longlong param_2,uint param_3,__acrt_ptd **param_4);
ulonglong FUN_14000f674(longlong *param_1,longlong param_2,int param_3);
undefined8 FUN_14000f758(FILE *param_1,longlong param_2,DWORD param_3,__acrt_ptd **param_4);
ulonglong FUN_14000f830(FILE *param_1,longlong param_2,uint param_3);
ulonglong operator()<>(undefined8 param_1,longlong *param_2,undefined8 *param_3,longlong *param_4);
ulonglong FUN_14000f908(undefined8 *param_1);
ulonglong FUN_14000f988(undefined8 param_1,longlong param_2,longlong param_3,longlong param_4,__acrt_ptd **param_5);
ulonglong FUN_14000fa24(undefined (*param_1) [32],ulonglong param_2,ulonglong param_3,FILE *param_4,__acrt_ptd **param_5);
ulonglong FUN_14000fc24(undefined8 param_1,longlong param_2,longlong param_3,longlong param_4);
ulonglong FUN_14000fcc8(longlong param_1,ulonglong param_2,longlong param_3);
ulonglong FUN_14000fd70(longlong param_1,ulonglong param_2,longlong param_3);
bool __crt_stdio_output::is_wide_character_specifier<wchar_t>(__uint64 param_1,wchar_t param_2,length_modifier param_3);
uint FUN_14000fe5c(__acrt_ptd **param_1,char **param_2,uint param_3,uint param_4);
uint FUN_14001010c(__acrt_ptd **param_1,ushort **param_2,uint param_3,uint param_4);
ulonglong FUN_140010864(longlong param_1);
ulonglong FUN_140010a4c(longlong param_1);
ulonglong FUN_140010c38(longlong param_1,byte param_2);
ulonglong FUN_140010e20(longlong param_1,byte param_2);
ulonglong FUN_14001100c(longlong param_1,byte param_2);
ulonglong FUN_1400111f4(longlong param_1,byte param_2);
void FUN_1400113e0(longlong param_1,uint param_2);
void FUN_14001145c(longlong param_1,uint param_2);
void FUN_1400114e4(longlong param_1,uint param_2,byte param_3);
void FUN_14001158c(longlong param_1,uint param_2,byte param_3);
void FUN_140011644(longlong param_1,uint param_2,byte param_3);
void FUN_1400116d0(longlong param_1,uint param_2,byte param_3);
void FUN_140011774(longlong param_1,ulonglong param_2);
void FUN_1400117f0(longlong param_1,ulonglong param_2);
void FUN_140011878(longlong param_1,ulonglong param_2,byte param_3);
void FUN_140011924(longlong param_1,ulonglong param_2,byte param_3);
void FUN_1400119e4(longlong param_1,ulonglong param_2,byte param_3);
void FUN_140011a70(longlong param_1,ulonglong param_2,byte param_3);
void FUN_140011b14(char *param_1,longlong *param_2);
ulonglong FUN_140011b80(longlong param_1,uint *param_2,undefined8 param_3,undefined4 param_4);
ulonglong FUN_140011c10(longlong param_1,uint *param_2,undefined8 param_3,undefined4 param_4);
undefined4 FUN_140011ca0(ulonglong *param_1,undefined8 param_2,ulonglong param_3,ulonglong param_4);
undefined4 FUN_140012024(__uint64 *param_1);
ulonglong FUN_1400122e8(ulonglong *param_1);
ulonglong FUN_14001246c(__uint64 *param_1);
void FUN_140012618(ulonglong *param_1);
void FUN_1400129e4(__uint64 *param_1);
undefined8 FUN_140012e40(longlong param_1);
undefined8 type_case_Z(__uint64 *param_1);
undefined8 FUN_140012f34(ulonglong *param_1);
undefined8 FUN_140013180(ulonglong *param_1);
undefined8 FUN_1400133e0(longlong param_1);
undefined8 FUN_1400134a4(__uint64 *param_1);
ulonglong FUN_140013568(longlong param_1);
undefined8 FUN_14001361c(longlong param_1);
undefined8 FUN_1400136b4(__uint64 *param_1);
int FUN_14001374c(longlong param_1,int param_2);
void FUN_1400137d0(__acrt_ptd **param_1);
void __thiscall __crt_stdio_output::string_output_adapter<char>::write_string(string_output_adapter<char> *this,char *param_1,int param_2,int *param_3,__crt_deferred_errno_cache *param_4);
void __thiscall __crt_stdio_output::string_output_adapter<wchar_t>::write_string(string_output_adapter<wchar_t> *this,wchar_t *param_1,int param_2,int *param_3,__crt_deferred_errno_cache *param_4);
void FUN_140013994(ulonglong param_1,undefined *param_2,ulonglong param_3,ulonglong param_4,undefined4 *param_5,undefined8 param_6);
void FUN_140013be8(ulonglong param_1,undefined2 *param_2,ulonglong param_3,longlong param_4,undefined4 *param_5,undefined8 param_6);
LPVOID _calloc_base(ulonglong param_1,ulonglong param_2);
void FUN_140013e4c(LPVOID param_1);
LPVOID _malloc_base(ulonglong param_1);
int strncmp(char *_Str1,char *_Str2,size_t _MaxCount);
undefined8 __acrt_initialize_stdio(void);
undefined * __acrt_iob_func(ulonglong param_1);
void __acrt_uninitialize_stdio(bool param_1);
void FUN_14001409c(longlong param_1);
void FUN_1400140a8(longlong param_1);
undefined * FUN_1400140b4(ulonglong param_1);
undefined4 __acrt_errno_from_os_error(int param_1);
void FUN_140014168(int param_1);
void FUN_1400141b0(int param_1,longlong param_2);
ulong * __doserrno(void);
ulong * __doserrno(void);
char * FUN_140014214(int param_1);
uint FUN_1400142b4(char *param_1,longlong param_2,undefined8 param_3,uint param_4);
undefined8 FUN_140014430(wchar_t *param_1,undefined (*param_2) [16]);
bool common_stat_handle_file_opened<struct__stat64i32>(wchar_t *param_1,int param_2,void *param_3,_stat64i32 *param_4);
void FUN_14001472c(FILETIME param_1);
_LocaleUpdate * __thiscall _LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,__crt_locale_pointers *param_1);
ushort convert_to_stat_mode(int param_1,wchar_t *param_2);
bool get_drive_number_from_path(wchar_t *param_1,int *param_2);
bool is_root_unc_name(wchar_t *param_1);
void FUN_140014aac(wchar_t *param_1);
ulonglong FUN_140014bbc(char *param_1,undefined (*param_2) [16]);
undefined8 thunk_FUN_140014430(wchar_t *param_1,undefined (*param_2) [16]);
ulonglong FUN_140014cc8(longlong param_1,longlong param_2);
char * strncat(char *_Dest,char *_Source,size_t _Count);
void FUN_140014e98(byte *param_1,byte *param_2);
ulong FUN_140014ec8(longlong param_1,LPCWSTR *param_2);
ulong FUN_140014f3c(longlong param_1,LPCWSTR *param_2);
undefined (*) [32] FUN_140015014(undefined8 *param_1);
undefined (*) [32] FUN_1400150f8(undefined (*param_1) [32],LPCWSTR param_2,ulonglong param_3);
FILE * FUN_140015278(wchar_t *param_1,wchar_t *param_2);
ulonglong FUN_140015284(ushort *param_1,byte *param_2,ulonglong param_3,__acrt_ptd **param_4);
ulonglong FUN_140015480(ushort *param_1,byte *param_2,ulonglong param_3);
errno_t _get_fmode(int *_PMode);
errno_t _set_fmode(int _Mode);
int FUN_14001558c(uint param_1,int param_2);
int _setmode_nolock(int _FileHandle,int _Mode);
void FUN_140015770(undefined8 param_1,longlong *param_2,longlong **param_3,longlong *param_4);
void FUN_14001580c(undefined8 param_1,int *param_2,int **param_3,int *param_4);
int FUN_1400158ec(undefined8 param_1,longlong *param_2,undefined8 *param_3,longlong *param_4);
int common_flush_all(bool param_1);
undefined8 FUN_14001598c(FILE *param_1,__acrt_ptd **param_2);
int FUN_140015a18(FILE *param_1);
int common_flush_all(bool param_1);
int fflush(FILE *_File);
char * strncpy(char *_Dest,char *_Source,size_t _Count);
wchar_t * _wcsdup(wchar_t *_Str);
short * FUN_140015d58(short *param_1,longlong param_2,longlong param_3);
ulonglong FUN_140015da0(undefined (*param_1) [32],ulonglong param_2);
ulonglong FUN_140015ef0(undefined (*param_1) [32],ulonglong param_2);
ulonglong common_putenv<>(undefined (*param_1) [32],undefined (*param_2) [32]);
undefined8 FUN_140016108(undefined (*param_1) [32],undefined (*param_2) [32]);
wchar_t * FUN_14001619c(undefined (*param_1) [32],undefined (*param_2) [32]);
ulonglong FUN_1400162f0(LPCWSTR param_1,LPCWSTR param_2);
errno_t FID_conflict:_putenv_s(wchar_t *_Name,wchar_t *_Value);
undefined8 FUN_14001647c(LPCWSTR param_1);
__int64 common_find_first_wide<struct__wfinddata64i32_t>(wchar_t *param_1,_wfinddata64i32_t *param_2);
int common_find_next_wide<struct__wfinddata64i32_t>(__int64 param_1,_wfinddata64i32_t *param_2);
__int64 convert_file_time_to_time_t<__int64>(_FILETIME *param_1);
undefined8 FUN_1400167a4(HANDLE param_1);
__int64 common_find_first_wide<struct__wfinddata64i32_t>(wchar_t *param_1,_wfinddata64i32_t *param_2);
int common_find_next_wide<struct__wfinddata64i32_t>(__int64 param_1,_wfinddata64i32_t *param_2);
undefined8 * __acrt_lowio_create_handle_array(void);
void __acrt_lowio_destroy_handle_array(LPCRITICAL_SECTION param_1);
longlong __acrt_lowio_ensure_fh_exists(uint param_1);
void __acrt_lowio_lock_fh(uint param_1);
undefined8 FUN_1400169a4(uint param_1,HANDLE param_2);
void __acrt_lowio_unlock_fh(uint param_1);
int _alloc_osfhnd(void);
undefined8 FUN_140016bcc(uint param_1);
undefined8 FUN_140016c88(uint param_1);
ulonglong operator()<>(undefined8 param_1,int *param_2,undefined8 param_3,int *param_4);
undefined8 FUN_140016d50(int param_1);
void_(__cdecl**___ptr64)(int) * get_global_action_nolock(int param_1);
void __acrt_get_sigabrt_handler(void);
void FUN_140016e58(undefined8 param_1);
undefined8 FUN_140016e78(uint param_1);
ulonglong FUN_1400170f8(uint param_1,ulonglong param_2);
undefined8 FUN_1400172d4(LPCWSTR param_1);
wchar_t * FUN_1400172fc(wchar_t *param_1,longlong param_2);
bool compute_name<wchar_t>(wchar_t *param_1,wchar_t *param_2,__uint64 param_3,__uint64 param_4);
short * FUN_140017630(short *param_1);
void FUN_1400176dc(wchar_t *param_1,longlong param_2);
errno_t clearerr_s(FILE *_File);
errno_t clearerr_s(FILE *_File);
ulonglong FUN_1400177a8(FILE *param_1,__acrt_ptd **param_2);
ulonglong FUN_140017814(FILE *param_1,__acrt_ptd **param_2);
longlong FUN_140017960(FILE *param_1,longlong param_2,longlong param_3,__acrt_ptd **param_4);
void FUN_140017ab8(FILE *param_1,LARGE_INTEGER param_2,__acrt_ptd **param_3);
longlong FUN_140017c3c(short *param_1,short *param_2,char param_3);
ulonglong FUN_140017c94(FILE *param_1);
ulonglong thunk_FUN_140017814(FILE *param_1,__acrt_ptd **param_2);
int iswctype(wint_t _C,wctype_t _Type);
undefined4 FUN_140017da4(int param_1,int *param_2);
undefined4 FUN_140017f28(void);
void FUN_140017f30(undefined4 param_1);
bool __acrt_has_user_matherr(void);
void FUN_140017f58(undefined8 param_1);
undefined8 FUN_140017f60(void);
void FUN_140017f98(ulonglong param_1);
void FUN_140017fc0(short *param_1,short **param_2,short *param_3,longlong *param_4,longlong *param_5);
LPVOID __acrt_allocate_buffer_for_argv(ulonglong param_1,ulonglong param_2,ulonglong param_3);
int _configure_wide_argv(int param_1);
undefined8 FUN_140018348(void);
undefined8 FUN_1400183bc(void);
char ** FUN_14001842c(char *param_1);
wchar_t ** FUN_14001853c(wchar_t *param_1);
void free_environment<>(LPVOID *param_1);
LPCWSTR FUN_14001869c(void);
longlong FUN_14001877c(void);
void uninitialize_environment_internal<>(undefined8 *param_1);
void uninitialize_environment_internal<>(undefined8 *param_1);
longlong FUN_140018870(void);
longlong __dcrt_get_or_create_wide_environment_nolock(void);
void FUN_1400188e8(void);
undefined8 thunk_FUN_1400183bc(void);
ushort * _get_wide_winmain_command_line(void);
void FUN_140018988(undefined **param_1,undefined **param_2);
undefined8 FUN_1400189cc(undefined **param_1,undefined **param_2);
void operator()<>(undefined8 param_1,int *param_2,int **param_3,int *param_4);
void FUN_140018a4c(int **param_1);
void FUN_140018be0(UINT param_1);
int FUN_140018c14(void);
void FUN_140018c44(void);
void FUN_140018cb4(undefined8 param_1);
void FUN_140018ccc(void);
void FUN_140018cdc(UINT param_1);
void FUN_140018ce8(ulonglong param_1);
void FUN_140018d28(UINT param_1);
void __thiscall __crt_seh_guarded_call<void>::operator()<class_<lambda_410d79af7f07d98d83a3f525b3859a53>,class_<lambda_3e16ef9562a7dcce91392c22ab16ea36>&___ptr64,class_<lambda_38119f0e861e05405d8a144b9b982f0a>_>(__crt_seh_guarded_call<void> *this,<lambda_410d79af7f07d98d83a3f525b3859a53> *param_1,<lambda_3e16ef9562a7dcce91392c22ab16ea36> *param_2,<lambda_38119f0e861e05405d8a144b9b982f0a> *param_3);
undefined4 FUN_140018da4(void);
void __acrt_uninitialize_locale(void);
int _configthreadlocale(int _Flag);
undefined4 FUN_140018e4c(void);
undefined4 * FUN_140018e80(void);
ulonglong operator()<>(undefined8 param_1,int *param_2,longlong **param_3,int *param_4);
ulonglong operator()<>(undefined8 param_1,int *param_2,longlong **param_3,int *param_4);
undefined8 FUN_140018f00(longlong **param_1);
undefined8 FUN_1400190b0(longlong **param_1);
void FUN_1400191d0(undefined8 param_1);
void FUN_1400191e0(longlong param_1);
undefined8 _initialize_onexit_table(longlong *param_1);
void _register_onexit_function(longlong param_1,undefined8 param_2);
undefined * FUN_1400192a0(void);
undefined8 FUN_1400192c0(void);
undefined FUN_1400192f0(void);
undefined FUN_140019300(void);
void FUN_140019340(void);
undefined8 FUN_140019350(void);
undefined FUN_140019390(void);
ulonglong FUN_1400193ec(void);
undefined8 FUN_140019400(bool param_1);
void FUN_140019438(void);
DWORD GetCurrentProcessId(void);
char * _strdup(char *_Src);
int _fileno(FILE *_File);
errno_t strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src);
void abort(void);
uint FUN_1400195c4(__acrt_ptd **param_1,wint_t **param_2,uint param_3,uint param_4);
int wcsncmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount);
__acrt_ptd * FUN_140019d78(__acrt_ptd **param_1);
longlong FUN_140019de4(longlong param_1,longlong param_2);
void __acrt_call_reportfault(int param_1,DWORD param_2,DWORD param_3);
void FUN_140019f8c(undefined8 param_1);
void FUN_140019f94(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5);
void FUN_14001a030(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5,__acrt_ptd **param_6);
void FUN_14001a100(void);
void _invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5);
void FUN_14001a168(LPVOID param_1);
ulonglong FUN_14001a1a4(undefined8 param_1,uint *param_2,uint **param_3,uint *param_4);
ulonglong FUN_14001a21c(uint param_1,__acrt_ptd **param_2);
ulonglong FUN_14001a2e0(uint param_1);
undefined8 FUN_14001a378(uint param_1,longlong param_2);
__crt_stdio_stream __acrt_stdio_allocate_stream(void);
undefined4 FUN_14001a4a0(undefined8 *param_1);
LPVOID * FUN_14001a4bc(LPVOID *param_1);
void __acrt_stdio_free_buffer_nolock(undefined8 *param_1);
void operator()<>(undefined8 param_1,int *param_2,longlong **param_3,int *param_4);
void operator()<>(undefined8 param_1,int *param_2,undefined8 *param_3,int *param_4);
void operator()<>(undefined8 param_1,int *param_2,undefined8 *param_3,int *param_4);
void operator()<>(undefined8 param_1,int *param_2,longlong **param_3,int *param_4);
void construct_ptd_array(__acrt_ptd *param_1);
void FUN_14001a7e0(__acrt_ptd *param_1);
void destroy_ptd_array(__acrt_ptd *param_1);
void replace_current_thread_locale_nolock(__acrt_ptd *param_1,__crt_locale_data *param_2);
__acrt_ptd * FUN_14001a960(void);
__acrt_ptd * FUN_14001aa34(void);
__acrt_ptd * FUN_14001aad8(void);
__acrt_ptd * FUN_14001aba0(undefined8 param_1,longlong param_2);
ulonglong __acrt_initialize_ptd(void);
undefined4 __acrt_uninitialize_ptd(void);
int FUN_14001acc4(uint param_1,short *param_2,longlong param_3);
int FUN_14001ae9c(uint param_1,byte *param_2,longlong param_3,undefined param_4,undefined4 param_5);
int FUN_14001b170(uint param_1,short *param_2,uint param_3);
int FUN_14001b28c(uint param_1,short *param_2,uint param_3);
ulonglong FUN_14001b6d8(FILE *param_1);
longlong FUN_14001b844(uint param_1,LARGE_INTEGER param_2,DWORD param_3,__acrt_ptd **param_4);
longlong FUN_14001b96c(uint param_1,LARGE_INTEGER param_2,DWORD param_3,longlong param_4);
longlong FUN_14001ba18(uint param_1,LARGE_INTEGER param_2,DWORD param_3);
longlong thunk_FUN_14001b844(uint param_1,LARGE_INTEGER param_2,DWORD param_3,__acrt_ptd **param_4);
longlong FUN_14001babc(uint param_1,LARGE_INTEGER param_2,DWORD param_3);
longlong thunk_FUN_14001b96c(uint param_1,LARGE_INTEGER param_2,DWORD param_3,longlong param_4);
void initialize_inherited_file_handles_nolock(void);
void FUN_14001bc50(void);
ulonglong __acrt_initialize_lowio(void);
undefined __acrt_uninitialize_lowio(void);
void FUN_14001bde0(undefined8 *param_1,uint param_2,undefined (*param_3) [32],ulonglong param_4,__acrt_ptd **param_5);
write_result write_text_ansi_nolock(int param_1,char *param_2,uint param_3);
write_result write_text_utf16le_nolock(int param_1,char *param_2,uint param_3);
write_result write_text_utf8_nolock(int param_1,char *param_2,uint param_3);
int FUN_14001c5fc(uint param_1,undefined (*param_2) [32],uint param_3);
int FUN_14001c694(uint param_1,undefined (*param_2) [32],uint param_3,__acrt_ptd **param_4);
int FUN_14001c7bc(uint param_1,undefined (*param_2) [32],uint param_3,__acrt_ptd **param_4);
bool FUN_14001cacc(undefined param_1,FILE *param_2,__acrt_ptd **param_3);
bool stream_is_at_end_of_file_nolock(__crt_stdio_stream param_1);
ulonglong FUN_14001cc40(byte param_1,FILE *param_2,__acrt_ptd **param_3);
ulonglong __acrt_should_use_temporary_buffer(FILE *param_1);
ulonglong __acrt_stdio_begin_temporary_buffering_nolock(FILE *param_1);
void FUN_14001ce14(char param_1,FILE *param_2,__acrt_ptd **param_3);
LPVOID _malloc_base(ulonglong param_1);
void FUN_14001ceb0(longlong param_1,longlong *param_2);
void FUN_14001cee4(longlong param_1,longlong *param_2,longlong param_3);
void FUN_14001cf1c(longlong param_1,longlong *param_2);
void FUN_14001cf50(longlong param_1,longlong *param_2,longlong param_3);
undefined8 FUN_14001cf88(double *param_1,undefined (*param_2) [16],undefined *param_3,char *param_4,rsize_t param_5,uint param_6,byte param_7,int param_8,__acrt_rounding_mode param_9,__acrt_ptd **param_10);
void FUN_14001d33c(ulonglong *param_1,undefined *param_2,undefined *param_3,char *param_4,rsize_t param_5,int param_6,char param_7,int param_8,int param_9,__acrt_ptd **param_10);
undefined8 FUN_14001d438(undefined *param_1,undefined *param_2,int param_3,char param_4,int param_5,int *param_6,byte param_7,__acrt_ptd **param_8);
void FUN_14001d61c(ulonglong *param_1,undefined (*param_2) [32],ulonglong param_3,char *param_4,rsize_t param_5,int param_6,int param_7,__acrt_ptd **param_8);
undefined8 FUN_14001d6f4(undefined (*param_1) [32],undefined8 param_2,int param_3,int *param_4,char param_5,__acrt_ptd **param_6);
void FUN_14001d84c(ulonglong *param_1,undefined (*param_2) [32],undefined *param_3,char *param_4,rsize_t param_5,int param_6,char param_7,int param_8,int param_9,__acrt_ptd **param_10);
bool should_round_up(double *param_1,__uint64 param_2,short param_3,__acrt_rounding_mode param_4);
undefined8 FUN_14001dab8(double *param_1,undefined (*param_2) [32],undefined *param_3,char *param_4,rsize_t param_5,int param_6,uint param_7,ulonglong param_8,uint param_9,__acrt_ptd **param_10);
undefined4 FUN_14001dda0(int *param_1,undefined (*param_2) [32],ulonglong param_3,WCHAR param_4,__acrt_ptd **param_5);
int FUN_14001df50(ushort *param_1,byte *param_2,ulonglong param_3,__acrt_ptd **param_4);
bool FUN_14001e0c8(void);
LPVOID _calloc_base(ulonglong param_1,ulonglong param_2);
FARPROC FUN_14001e158(uint param_1,LPCSTR param_2,uint *param_3,uint *param_4);
INT_PTR FUN_14001e318(undefined8 param_1);
INT_PTR FUN_14001e370(void);
void FUN_14001e3b4(ushort *param_1,DWORD param_2,PCNZWCH param_3,int param_4,PCNZWCH param_5,int param_6);
DWORD FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback);
BOOL FlsFree(DWORD dwFlsIndex);
PVOID FlsGetValue(DWORD dwFlsIndex);
BOOL FlsSetValue(DWORD dwFlsIndex,PVOID lpFlsData);
void FUN_14001e4c0(LPCRITICAL_SECTION param_1,DWORD param_2);
void FUN_14001e530(ushort *param_1,DWORD param_2,LPCWSTR param_3,int param_4,LPWSTR param_5,int param_6);
void FUN_14001e61c(ushort *param_1);
undefined8 FUN_14001e680(void);
undefined8 __acrt_uninitialize_winapi_thunks(char param_1);
int FUN_14001e6f4(void);
undefined ** FUN_14001e7a8(void);
undefined * FUN_14001e7b0(void);
ulong FUN_14001e7b8(char *param_1,longlong param_2,longlong param_3,longlong param_4);
int _getdrive(void);
wchar_t * wcspbrk(wchar_t *_Str,wchar_t *_Control);
void __ascii_wcsicmp(ushort *param_1,ushort *param_2);
ulonglong FUN_14001ea14(WCHAR *param_1,WCHAR *param_2);
void __acrt_MultiByteToWideChar(uint param_1,ulonglong param_2);
bool __crt_time_is_leap_year<int>(int param_1);
__int64 common_loctotime_t<__int64>(int param_1,int param_2,int param_3,int param_4,int param_5,int param_6,int param_7);
__int64 common_loctotime_t<__int64>(int param_1,int param_2,int param_3,int param_4,int param_5,int param_6,int param_7);
ulonglong operator()<>(undefined8 param_1,longlong *param_2,ulonglong **param_3,longlong *param_4);
undefined8 FUN_14001eeb4(ulonglong **param_1);
void FUN_14001f200(uint param_1,undefined2 *param_2,int param_3);
int is_valid_drive(uint param_1);
void FUN_14001f3fc(undefined2 *param_1,int param_2);
void __acrt_WideCharToMultiByte(uint param_1,uint param_2,LPCWSTR param_3,int param_4,LPSTR param_5,int param_6,LPBOOL param_7,LPBOOL param_8);
__acrt_stdio_stream_mode __acrt_stdio_parse_mode<wchar_t>(wchar_t *param_1);
FILE * _wopenfile(wchar_t *_Filename,wchar_t *_Mode,int _ShFlag,FILE *_File);
void FUN_14001f874(undefined2 *param_1,byte *param_2,ulonglong param_3,undefined8 *param_4,longlong param_5);
longlong FUN_14001f8b8(ushort *param_1,byte **param_2,ulonglong param_3,undefined8 *param_4,longlong param_5);
undefined8 FUN_14001fa60(void);
undefined8 __acrt_initialize_locks(void);
void __acrt_lock(int param_1);
undefined8 __acrt_uninitialize_locks(void);
void __acrt_unlock(int param_1);
undefined8 FUN_14001fb44(undefined8 param_1,uint *param_2,uint **param_3,uint *param_4);
int _commit(int _FileHandle);
errno_t wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src);
LPVOID _realloc_base(LPVOID param_1,ulonglong param_2);
byte * FUN_14001fd48(byte *param_1,int param_2);
undefined (*) [32] FUN_1400200a0(undefined (*param_1) [32],int param_2);
char ** copy_environment<char>(char **param_1);
wchar_t ** copy_environment<wchar_t>(wchar_t **param_1);
byte * thunk_FUN_14001fd48(byte *param_1,int param_2);
undefined (*) [32] thunk_FUN_1400200a0(undefined (*param_1) [32],int param_2);
ulong FUN_1400206c0(uint param_1,short *param_2,ulonglong param_3,uint param_4,byte param_5);
errno_t FID_conflict:_ultow_s(ulong _Val,char *_DstBuf,size_t _Size,int _Radix);
undefined8 FUN_140020740(wchar_t **param_1,ulonglong *param_2,wchar_t *param_3);
wchar_t * common_getenv_nolock<wchar_t>(wchar_t *param_1);
int common_getenv_s<wchar_t>(__uint64 *param_1,wchar_t *param_2,__uint64 param_3,wchar_t *param_4);
void FUN_1400209c8(wchar_t **param_1,ulonglong *param_2,wchar_t *param_3);
int common_getenv_s<wchar_t>(__uint64 *param_1,wchar_t *param_2,__uint64 param_3,wchar_t *param_4);
ulong FUN_1400209f0(short *param_1,longlong param_2,longlong param_3);
errno_t _waccess_s(wchar_t *_Filename,int _AccessMode);
int FUN_140020b20(void);
BOOL GetStringTypeW(DWORD dwInfoType,LPCWSTR lpSrcStr,int cchSrc,LPWORD lpCharType);
ulong FUN_140020bd0(short *param_1,longlong param_2,longlong param_3,longlong param_4);
ulonglong FUN_140020cd0(ulonglong param_1,ulonglong param_2);
void FUN_140020ce4(wchar_t **param_1,LPVOID *param_2);
int copy_and_add_argument_to_buffer<wchar_t>(wchar_t *param_1,wchar_t *param_2,__uint64 param_3,argument_list<wchar_t> *param_4);
void thunk_FUN_140020ce4(wchar_t **param_1,LPVOID *param_2);
void FUN_140021268(undefined8 param_1,int *param_2,longlong **param_3,int *param_4);
int getSystemCP(int param_1);
void FUN_1400214b8(longlong param_1);
void FUN_140021550(longlong param_1);
int FUN_140021738(int param_1,char param_2,__acrt_ptd *param_3,__crt_multibyte_data **param_4);
__crt_multibyte_data *update_thread_multibyte_data_internal(__acrt_ptd *param_1,__crt_multibyte_data **param_2);
undefined8 __acrt_initialize_multibyte(void);
void FUN_140021ac0(void);
void FUN_140021adc(int param_1,longlong param_2);
LPSTR FUN_140021d9c(void);
undefined (*) [32] FUN_140021eac(void);
undefined4 __acrt_get_process_end_policy(void);
UINT ___lc_codepage_func(void);
void __acrt_locale_free_monetary(longlong param_1);
void __acrt_locale_free_numeric(longlong *param_1);
void FUN_14002212c(undefined8 *param_1,longlong param_2);
void __acrt_locale_free_time(undefined8 *param_1);
void FUN_140022268(__crt_locale_pointers *param_1,DWORD param_2,undefined8 param_3,undefined8 param_4,LPWORD param_5,uint param_6,int param_7);
int FUN_140022404(longlong param_1);
void __acrt_free_locale(longlong param_1);
void __acrt_locale_free_lc_time_if_unreferenced(undefined **param_1);
int __acrt_locale_release_lc_time_reference(undefined **param_1);
void __acrt_release_locale_ref(longlong param_1);
undefined ** FUN_140022738(void);
undefined ** _updatetlocinfoEx_nolock(longlong *param_1,undefined **param_2);
LPVOID _recalloc_base(LPCVOID param_1,ulonglong param_2,ulonglong param_3);
bool FUN_1400228b0(void);
undefined FUN_1400228d0(void);
void FUN_1400229b8(undefined8 param_1);
undefined8 FUN_1400229c0(void);
ulonglong _query_new_handler(void);
byte FUN_140022a30(uint param_1);
void FUN_140022a90(longlong *param_1);
wint_t _putwch_nolock(wchar_t _WCh);
undefined4 FUN_140022b38(undefined (*param_1) [32],ulonglong param_2,int param_3,int *param_4,int param_5,int param_6,__acrt_ptd **param_7);
ulonglong FUN_140022cc0(uint *param_1,uint *param_2,undefined param_3,undefined param_4,undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined param_9,undefined param_10,undefined8 param_11,undefined4 param_12,undefined8 param_13,undefined4 param_14,undefined4 param_15);
void FUN_14002314c(ulonglong param_1,int param_2,int param_3,undefined4 *param_4,char *param_5,rsize_t param_6);
errno_t memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount);
uint FUN_140024414(void);
undefined8 FUN_140024428(byte *param_1,uint param_2,undefined8 *param_3,longlong param_4);
undefined4 FUN_1400244cc(ushort *param_1);
WCHAR FUN_140024574(WCHAR param_1,__crt_locale_pointers *param_2);
undefined8 FUN_140024670(void);
undefined4 * FUN_1400246c0(void);
undefined4 * FUN_1400246c8(void);
undefined4 * FUN_1400246d0(void);
undefined8 FUN_1400246d8(void);
undefined8 FUN_1400246e0(void);
errno_t _get_daylight(int *_Daylight);
errno_t _get_dstbias(long *_Daylight_savings_bias);
errno_t _get_timezone(long *_Timezone);
int _isindst_nolock(tm *param_1);
void cvtdate(transition_type param_1,date_type param_2,int param_3,int param_4,int param_5,int param_6,int param_7,int param_8,int param_9,int param_10,int param_11);
void tzset_env_copy_to_tzname(wchar_t *param_1,wchar_t *param_2,char *param_3,__uint64 param_4);
void FUN_140024d48(wchar_t *param_1);
void tzset_from_system_nolock(void);
void FUN_14002514c(void);
void tzset_os_copy_to_tzname(wchar_t *param_1,wchar_t *param_2,char *param_3,uint param_4);
void __tzset(void);
int _isindst(tm *_Time);
int __ascii_wcsnicmp(ushort *param_1,ushort *param_2,longlong param_3);
int FUN_140025398(WCHAR *param_1,WCHAR *param_2,longlong param_3);
int _strnicmp_l(char *_Str1,char *_Str2,size_t _MaxCount,_locale_t _Locale);
ulong common_sopen_dispatch<>(LPCWSTR param_1,uint param_2,int param_3,ulonglong param_4,uint *param_5,int param_6);
ulonglong FUN_140025740(uint param_1,byte *param_2,uint param_3,char *param_4);
file_options decode_options(int param_1,int param_2,int param_3);
int truncate_ctrl_z_if_present(int param_1);
ulong FUN_140025c88(undefined4 *param_1,uint *param_2,LPCWSTR param_3,uint param_4,int param_5);
errno_t FID_conflict:_sopen_s(int *_FileHandle,char *_Filename,int _OpenFlag,int _ShareFlag,int _PermissionMode);
void FUN_1400260ac(ulonglong param_1,byte *param_2,ulonglong param_3,undefined8 *param_4,longlong param_5);
int FUN_140026288(undefined (*param_1) [32],undefined (*param_2) [32],ulonglong param_3);
int FUN_1400263c8(byte *param_1,byte *param_2,size_t param_3);
LPCWSTR FUN_1400264e0(char *param_1,char *param_2);
void FUN_140026680(void);
void FUN_1400266e0(undefined *param_1,ulonglong param_2,ulonglong param_3,undefined *param_4);
void FUN_140026af0(longlong *param_1,ushort *param_2,uint param_3,char *param_4,int param_5,undefined8 param_6,int param_7,uint param_8,int param_9);
void __acrt_LCMapStringA(__crt_locale_pointers *param_1,ushort *param_2,uint param_3,char *param_4,int param_5,undefined8 param_6,int param_7,uint param_8,int param_9);
bool FUN_140026eb0(void);
SIZE_T _msize_base(LPCVOID param_1);
bool __dcrt_lowio_ensure_console_output_initialized(void);
void FUN_140026f60(void);
BOOL __dcrt_write_console(void *param_1,DWORD param_2,LPDWORD param_3);
errno_t _controlfp_s(uint *_CurrentState,uint _NewValue,uint _Mask);
undefined8 fegetenv(uint *param_1);
undefined8 fesetenv(int *param_1);
undefined8 feholdexcept(undefined8 *param_1);
double FUN_14002715c(double param_1);
double log10(double _X);
uint FUN_1400277d8(void);
uint FUN_1400278bc(void);
void FUN_140027914(void);
void FUN_140027a50(void);
undefined8 FUN_140027ac4(undefined8 param_1,undefined8 *param_2);
undefined8 FUN_140027acc(undefined8 *param_1,longlong param_2);
void __acrt_LCMapStringW(ushort *param_1,DWORD param_2,undefined (*param_3) [32],int param_4,LPWSTR param_5,int param_6);
uint FUN_140027b68(wint_t *param_1,wint_t **param_2,uint param_3,undefined4 param_4);
undefined4 FUN_140027c1c(uint param_1,longlong param_2);
undefined4 FUN_140027cb4(uint param_1,longlong param_2,__acrt_ptd **param_3);
ulonglong __acrt_CompareStringW(ushort *param_1,DWORD param_2,undefined (*param_3) [32],int param_4,undefined (*param_5) [32],int param_6);
void FUN_140027f08(longlong *param_1,ushort *param_2,DWORD param_3,byte *param_4,int param_5,byte *param_6,int param_7,uint param_8);
void __acrt_CompareStringA(__crt_locale_pointers *param_1,ushort *param_2,DWORD param_3,byte *param_4,int param_5,byte *param_6,int param_7,uint param_8);
size_t __strncnt(char *_String,size_t _Cnt);
uint _clearfp(void);
uint _control87(uint _NewValue,uint _Mask);
uint _control87(uint _NewValue,uint _Mask);
undefined8 _call_matherr(int param_1,undefined param_2,undefined param_3,undefined param_4,undefined8 param_5,undefined8 param_6,undefined8 param_7);
bool _exception_enabled(uint param_1,ulonglong param_2);
void _handle_error(undefined8 param_1,uint param_2,undefined8 param_3,int param_4,uint param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9);
undefined8 __acrt_initialize_fma3(void);
void _log10_special(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,int param_5);
undefined8 _log_special_common(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,int param_5,uint param_6,undefined param_7,undefined param_8,undefined param_9,undefined param_10,undefined8 param_11);
undefined4 _get_fpsr(void);
void FUN_140028a20(void);
void _fclrf(void);
void _raise_exc(uint *param_1,ulonglong *param_2,ulonglong param_3,uint param_4,undefined8 *param_5,undefined8 *param_6);
void _raise_exc_ex(uint *param_1,ulonglong *param_2,ulonglong param_3,uint param_4,undefined8 *param_5,undefined8 *param_6,int param_7);
void _set_errno_from_matherr(int param_1);
uint _clrfp(void);
uint _ctrlfp(uint param_1,uint param_2);
void _set_statfp(void);
uint _statfp(void);
PIMAGE_SECTION_HEADER _FindPESection(PBYTE pImageBase,DWORD_PTR rva);
BOOL _IsNonwritableInCurrentImage(PBYTE pTarget);
bool FUN_140028f40(short *param_1);
undefined8 * FUN_140028f70(undefined8 *param_1,ulonglong param_2);
void thunk_FUN_140029024(void);
void FID_conflict:__GSHandlerCheck_EH(int *param_1,ulonglong param_2,_CONTEXT *param_3,ulonglong *param_4);
void FUN_140029024(void);
void __C_specific_handler_noexcept(PEXCEPTION_RECORD param_1,PVOID param_2,longlong param_3,longlong *param_4);
undefined (*) [16] FUN_140029078(undefined (*param_1) [16],ushort param_2);
void _guard_dispatch_icall(void);
void _guard_dispatch_icall(void);
void FUN_140029170(int **param_1);
void FUN_1400292cd(_EXCEPTION_POINTERS *param_1,longlong param_2);
void FUN_140029378(int **param_1);
void FUN_14002938e(void);
void FUN_1400293b1(undefined8 param_1,longlong param_2);
void FUN_1400293c9(undefined8 param_1,longlong param_2);
void FUN_1400293e1(undefined8 param_1,longlong param_2);
void FUN_1400293fc(undefined8 param_1,longlong param_2);
void FUN_140029427(undefined8 param_1,longlong param_2);
void FUN_14002943e(undefined8 param_1,longlong param_2);
void FUN_14002945b(void);
void FUN_140029474(void);
void FUN_14002948d(undefined8 param_1,longlong param_2);
void FUN_1400294a7(void);
void FUN_1400294c0(undefined8 param_1,longlong param_2);
void FUN_1400294e1(void);
void FUN_1400294fa(undefined8 param_1,longlong param_2);
undefined4 FUN_140029512(int **param_1,longlong param_2);
void FUN_14002953f(undefined8 param_1,longlong param_2);
void FUN_140029559(undefined8 param_1,longlong param_2);
void FUN_140029573(void);
void FUN_14002958c(undefined8 param_1,longlong param_2);
void FUN_1400295a3(void);
void FUN_1400295bc(undefined8 param_1,longlong param_2);
void FUN_1400295d6(void);
void FUN_1400295ef(undefined8 param_1,longlong param_2);
void FUN_140029609(void);
void FUN_140029622(void);
void FUN_14002963b(void);
void FUN_140029651(void);
void FUN_14002966a(undefined8 param_1,longlong param_2);
undefined8 FUN_1400296bd(int **param_1);
bool FUN_1400296f0(int **param_1);

