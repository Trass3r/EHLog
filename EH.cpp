
// uses http://stacktrace.sourceforge.net and https://stackwalker.codeplex.com/
// to hijack thrown exceptions and print stack trace
// just add to your project

#ifdef _WIN32

#include "call_stack.hpp"

#define NOMINMAX
#include <windows.h>
#include <assert.h>


const DWORD NT_EXCEPTION = 0xE06D7363; // 'msc' | 0xE0000000
const DWORD EH_MAGIC1 = 0x19930520;
const DWORD EH_PURE_MAGIC1 = 0x01994000;

// generate stack frame pointers
#pragma optimize("y", off)

__declspec(noreturn)
extern "C"
void __stdcall _CxxThrowException(void* exceptionObj,
                                  _ThrowInfo* pTI)
{
	PVOID baseOfImage = nullptr;
#if _WIN64
	RtlPcToFileHeader((PVOID)pTI, &baseOfImage);
#endif

	bool pureModule = pTI && (
		(pTI->attributes & 8)
#if _WIN64
		|| !baseOfImage
#endif
		);

	stacktrace::call_stack cs(1);
	std::string s = cs.to_string();

	printf("\n--------\nException occured: %s\n--------\n", s.c_str());

	const ULONG_PTR args[] = { pureModule ? EH_PURE_MAGIC1 : EH_MAGIC1,
	                           (ULONG_PTR)exceptionObj,
	                           (ULONG_PTR)pTI
#if _WIN64
	                           ,(ULONG_PTR)baseOfImage
#endif
	};

	RaiseException(NT_EXCEPTION,
		EXCEPTION_NONCONTINUABLE,
		sizeof(args) / sizeof(args[0]),
		args);
}

// restore commandline optimization settings
#pragma optimize("", on)

namespace
{
//! overwrite the runtime _CxxThrowException
//! so linked in libraries will also use our version
struct PatchDllCxxThrow
{
	PatchDllCxxThrow()
	{
		// find the right library
		HMODULE hmsvc = LoadLibraryA(
#if _MSC_VER >= 1920
#error "not supported yet"
#elif _MSC_VER >= 1900 // VS 2015-17
	"vcruntime140"
#elif _MSC_VER >= 1800 // VS 2013
	"msvcr120"
#elif _MSC_VER >= 1700 // VS 2012
	"msvcr110"
#elif _MSC_VER >= 1600 // VS 2010
	"msvcr100"
#else
#error "not supported"
#endif

#if _DEBUG || !defined(NDEBUG)
		"d"
#endif
		".dll");

		if (!hmsvc)
		{
			assert(0 && "Could not load runtime library");
			return;
		}

		void *pOrgEntry = GetProcAddress(hmsvc, "_CxxThrowException");
		if (!pOrgEntry)
		{
			assert(0 && "Could not get address of _CxxThrowException");
			return;
		}

		ptrdiff_t p = (ptrdiff_t)_CxxThrowException;

#if _M_X64
		// 48 b8 35 08 40 00 00 00 00 00   mov rax, 0x0000000000400835
		// ff e0                           jmp rax
		unsigned char codeBytes[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   0xff, 0xe0 };
		memcpy(&codeBytes[2], &p, sizeof(void*));
#elif _M_IX86
		// E9 00000000   jmp rel  displacement relative to next instruction
		unsigned char codeBytes[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
		p -= (ptrdiff_t)pOrgEntry + sizeof(codeBytes);
		memcpy(&codeBytes[1], &p, sizeof(void*));
#else
#error "The following code only works for x86 and x64!"
#endif

		SIZE_T bytesWritten = 0;
		BOOL res = WriteProcessMemory(GetCurrentProcess(),
			pOrgEntry, codeBytes, sizeof(codeBytes), &bytesWritten);

		assert(res && bytesWritten == sizeof(codeBytes));
	}
} _dummy;
}

#endif
