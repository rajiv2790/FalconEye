#pragma once
#define CALLBACK   __stdcall

#define SELF_PROCESS_HANDLE (HANDLE)0xffffffffffffffff
#define MEM_IMAGE 0x1000000
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ

typedef UINT_PTR WPARAM;
typedef LONG_PTR LPARAM;
typedef USHORT* PRTL_ATOM;
typedef unsigned short  WORD;
typedef unsigned int    UINT;
typedef unsigned short  ATOM;
typedef unsigned int    BOOL;
typedef unsigned long   DWORD;
typedef unsigned long   LRESULT;
typedef HANDLE HWND;
typedef HANDLE HHOOK;
typedef HANDLE HMODULE, HINSTANCE;

typedef LRESULT(*HOOKPROC)(
	int code,
	WPARAM wParam, 
	LPARAM lParam);

typedef struct _INITIAL_TEB {
	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;

typedef struct _LPC_SECTION_OWNER_MEMORY {
	ULONG                   Length;
	HANDLE                  SectionHandle;
	ULONG                   OffsetInSection;
	ULONG                   ViewSize;
	PVOID                   ViewBase;
	PVOID                   OtherSideViewBase;
} LPC_SECTION_OWNER_MEMORY, * PLPC_SECTION_OWNER_MEMORY;

typedef struct _LPC_SECTION_MEMORY {
	ULONG                   Length;
	ULONG                   ViewSize;
	PVOID                   ViewBase;
} LPC_SECTION_MEMORY, * PLPC_SECTION_MEMORY;

typedef struct tagMOUSEINPUT {
    LONG    dx;
    LONG    dy;
    DWORD   mouseData;
    DWORD   dwFlags;
    DWORD   time;
    ULONG_PTR dwExtraInfo;
} MOUSEINPUT, * PMOUSEINPUT, FAR* LPMOUSEINPUT;

typedef struct tagKEYBDINPUT {
    WORD    wVk;
    WORD    wScan;
    DWORD   dwFlags;
    DWORD   time;
    ULONG_PTR dwExtraInfo;
} KEYBDINPUT, * PKEYBDINPUT, FAR* LPKEYBDINPUT;

typedef struct tagHARDWAREINPUT {
    DWORD   uMsg;
    WORD    wParamL;
    WORD    wParamH;
} HARDWAREINPUT, * PHARDWAREINPUT, FAR* LPHARDWAREINPUT;

typedef struct tagINPUT {
    DWORD   type;
    union
    {
        MOUSEINPUT      mi;
        KEYBDINPUT      ki;
        HARDWAREINPUT   hi;
    } DUMMYUNIONNAME;
} INPUT, * PINPUT, FAR* LPINPUT;

typedef struct _WNF_TYPE_ID {
    GUID                              TypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;

typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;

typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;
