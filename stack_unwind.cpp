#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <assert.h>
#define _NO_CVCONST_H
#include <dbghelp.h>


#pragma comment(lib, "dbghelp.lib")

#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10

static_assert(_WIN64, "Only implemented for x64 right now");

static void InitDbgHelp()
{
	DWORD SymOpts = SymGetOptions();
	
	SymOpts |= SYMOPT_LOAD_LINES;
	SymOpts |= SYMOPT_FAIL_CRITICAL_ERRORS;
	SymOpts |= SYMOPT_DEFERRED_LOADS;
	SymOpts |= SYMOPT_EXACT_SYMBOLS;
	SymOpts |= SYMOPT_UNDNAME;
	
	SymSetOptions(SymOpts);
	
	SymInitializeW(GetCurrentProcess(), nullptr, true);
}

static void UninitDbgHelp()
{
	SymCleanup(GetCurrentProcess());
}

int BackTraceStackHelper(
	STACKFRAME64* StackFrames,
	CONTEXT* ThreadContexts,
	int* NumFrames,
	int MaxNumFrames,
	const CONTEXT* ThreadContext)
{
	if (MaxNumFrames <= 0)
	{
		return EXCEPTION_EXECUTE_HANDLER;
	}
	
	__try
	{
		HANDLE ProcessHandle = GetCurrentProcess();
		HANDLE ThreadHandle = GetCurrentThread();
		CONTEXT CurContext = *ThreadContext;
		STACKFRAME64 CurFrame = {};
		CurFrame.AddrPC.Mode = AddrModeFlat;
		CurFrame.AddrStack.Mode = AddrModeFlat;
		CurFrame.AddrFrame.Mode = AddrModeFlat;
		CurFrame.AddrPC.Offset = CurContext.Rip;
		CurFrame.AddrStack.Offset = CurContext.Rsp;
		CurFrame.AddrFrame.Offset = CurContext.Rbp;
		
		int& Depth = *NumFrames;
		Depth = 0;
		StackFrames[Depth] = CurFrame;
		ThreadContexts[Depth] = CurContext;
		++Depth;
		
		while (Depth < MaxNumFrames)
		{
			bool bSucceed = !!StackWalk64(
				IMAGE_FILE_MACHINE_AMD64,
				ProcessHandle,
				ThreadHandle,
				&CurFrame,
				&CurContext,
				NULL,
				&SymFunctionTableAccess64,
				&SymGetModuleBase64,
				NULL);
			
			if (!bSucceed || !CurFrame.AddrFrame.Offset) break;
			
			StackFrames[Depth] = CurFrame;
			ThreadContexts[Depth] = CurContext;
			++Depth;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return EXCEPTION_EXECUTE_HANDLER;
	}
	return EXCEPTION_EXECUTE_HANDLER;
}	

std::string SymFlag2Str(int SymFlag, const char* Prefix = "")
{
	if (!SymFlag) return "";
	
	int LSBit = SymFlag & -SymFlag;
	std::string s;
	switch (LSBit)
	{
	case SYMFLAG_VALUEPRESENT:
		s = "SYMFLAG_VALUEPRESENT";
		break;
	case SYMFLAG_REGISTER:
		s = "SYMFLAG_REGISTER";
		break;
	case SYMFLAG_REGREL:
		s = "SYMFLAG_REGREL";
		break;
	case SYMFLAG_FRAMEREL:
		s = "SYMFLAG_FRAMEREL";
		break;
	case SYMFLAG_PARAMETER:
		s = "SYMFLAG_PARAMETER";
		break;
	case SYMFLAG_LOCAL:
		s = "SYMFLAG_LOCAL";
		break;
	case SYMFLAG_CONSTANT:
		s = "SYMFLAG_CONSTANT";
		break;
	case SYMFLAG_EXPORT:
		s = "SYMFLAG_EXPORT";
		break;
	case SYMFLAG_FORWARDER:
		s = "SYMFLAG_FORWARDER";
		break;
	case SYMFLAG_FUNCTION:
		s = "SYMFLAG_FUNCTION";
		break;
	case SYMFLAG_VIRTUAL:
		s = "SYMFLAG_VIRTUAL";
		break;
	case SYMFLAG_THUNK:
		s = "SYMFLAG_THUNK";
		break;
	case SYMFLAG_TLSREL:
		s = "SYMFLAG_TLSREL";
		break;
	case SYMFLAG_SLOT:
		s = "SYMFLAG_SLOT";
		break;
	case SYMFLAG_ILREL:
		s = "SYMFLAG_ILREL";
		break;
	case SYMFLAG_METADATA:
		s = "SYMFLAG_METADATA";
		break;
	case SYMFLAG_CLR_TOKEN:
		s = "SYMFLAG_CLR_TOKEN";
		break;
	case SYMFLAG_NULL:
		s = "SYMFLAG_NULL";
		break;
	case SYMFLAG_FUNC_NO_RETURN:
		s = "SYMFLAG_FUNC_NO_RETURN";
		break;
	case SYMFLAG_SYNTHETIC_ZEROBASE:
		s = "SYMFLAG_SYNTHETIC_ZEROBASE";
		break;
	case SYMFLAG_PUBLIC_CODE:
		s = "SYMFLAG_PUBLIC_CODE";
		break;
	default:
		s = "?";
		break;
	}
	SymFlag ^= LSBit;
	return Prefix + s + SymFlag2Str(SymFlag, " | ");
}

std::string SymTag2Str(int SymTag)
{
#define CASE_SYMTAGENUM(X) case X: return #X
	switch(SymTag)
	{
	CASE_SYMTAGENUM(SymTagNull);
    CASE_SYMTAGENUM(SymTagExe);
    CASE_SYMTAGENUM(SymTagCompiland);
    CASE_SYMTAGENUM(SymTagCompilandDetails);
    CASE_SYMTAGENUM(SymTagCompilandEnv);
    CASE_SYMTAGENUM(SymTagFunction);
    CASE_SYMTAGENUM(SymTagBlock);
    CASE_SYMTAGENUM(SymTagData);
    CASE_SYMTAGENUM(SymTagAnnotation);
    CASE_SYMTAGENUM(SymTagLabel);
    CASE_SYMTAGENUM(SymTagPublicSymbol);
    CASE_SYMTAGENUM(SymTagUDT);
    CASE_SYMTAGENUM(SymTagEnum);
    CASE_SYMTAGENUM(SymTagFunctionType);
    CASE_SYMTAGENUM(SymTagPointerType);
    CASE_SYMTAGENUM(SymTagArrayType);
    CASE_SYMTAGENUM(SymTagBaseType);
    CASE_SYMTAGENUM(SymTagTypedef);
    CASE_SYMTAGENUM(SymTagBaseClass);
    CASE_SYMTAGENUM(SymTagFriend);
    CASE_SYMTAGENUM(SymTagFunctionArgType);
    CASE_SYMTAGENUM(SymTagFuncDebugStart);
    CASE_SYMTAGENUM(SymTagFuncDebugEnd);
    CASE_SYMTAGENUM(SymTagUsingNamespace);
    CASE_SYMTAGENUM(SymTagVTableShape);
    CASE_SYMTAGENUM(SymTagVTable);
    CASE_SYMTAGENUM(SymTagCustom);
    CASE_SYMTAGENUM(SymTagThunk);
    CASE_SYMTAGENUM(SymTagCustomType);
    CASE_SYMTAGENUM(SymTagManagedType);
    CASE_SYMTAGENUM(SymTagDimension);
    CASE_SYMTAGENUM(SymTagCallSite);
    CASE_SYMTAGENUM(SymTagMax);
	default: return "?";
	}
#undef CASE_SYMTAGENUM	
}

void BackTraceStack(
	STACKFRAME64* StackFrames,
	CONTEXT* ThreadContexts,
	int* NumFrames,
	int MaxNumFrames)
{
	__try
	{
		RaiseException(0, 0, 0, NULL);
	}
	__except(BackTraceStackHelper(
		StackFrames,
		ThreadContexts,
		NumFrames,
		MaxNumFrames,
		(GetExceptionInformation())->ContextRecord))
	{
	}
}

void PrintSymbolInfo(const SYMBOL_INFO& SymbolInfo, const char* Indent = "")
{
	printf(
		"%sSYMBOL_INFO {\n"
		"%s  Name=%s\n"
		"%s  TypeIndex=%d\n"
		"%s  Index=%d\n"
		"%s  Size=%d\n"
		"%s  ModBase=0x%llx\n"
		"%s  Flags=%s\n"
		"%s  Value=%lld\n"
		"%s  Address=0x%llx\n"
		"%s  Register=%d\n"
		"%s  Scope=%d\n"
		"%s  Tag=%s\n"
		"%s}\n",
		Indent,
		Indent, SymbolInfo.Name,
		Indent, SymbolInfo.TypeIndex,
		Indent, SymbolInfo.Index,
		Indent, SymbolInfo.Size,
		Indent, SymbolInfo.ModBase,
		Indent, SymFlag2Str(SymbolInfo.Flags).c_str(),
		Indent, SymbolInfo.Value,
		Indent, SymbolInfo.Address,
		// Looks like 335 stands for RSP and 334 for RBP if
		// SYMFLAG_REGREL is in Flags but no doc can be found
		// to support this mapping
		Indent, SymbolInfo.Register,
		Indent, SymbolInfo.Scope,
		Indent, SymTag2Str(SymbolInfo.Tag).c_str(),
		Indent);
}

void PrintStackFrame64(const STACKFRAME64& Frame, const char* Indent = "")
{
	printf(
		"%sSTACKFRAME64 {\n"
		"%s  PC=0x%llx\n"
		"%s  RetAddr=0x%llx\n"
		"%s  FP=0x%llx\n"
		"%s  SP=0x%llx\n"
		"%s  Params=0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"%s}\n",
		Indent,
		Indent, Frame.AddrPC.Offset,
		Indent, Frame.AddrReturn.Offset,
		Indent, Frame.AddrFrame.Offset,
		Indent, Frame.AddrStack.Offset,
		Indent, Frame.Params[0], Frame.Params[1], Frame.Params[2], Frame.Params[3],
		Indent);
}

static inline IMAGEHLP_STACK_FRAME StackFrame64ToImageHlpStackFrame(
	const STACKFRAME64& Frame)
{
	IMAGEHLP_STACK_FRAME Ret = {};
	Ret.InstructionOffset = Frame.AddrPC.Offset;
	Ret.ReturnOffset = Frame.AddrReturn.Offset;
	Ret.FrameOffset = Frame.AddrFrame.Offset;
	Ret.StackOffset = Frame.AddrStack.Offset;
	Ret.BackingStoreOffset = Frame.AddrBStore.Offset;
	Ret.FuncTableEntry = (ULONG64)Frame.FuncTableEntry;
	memcpy(Ret.Params, Frame.Params, sizeof(Ret.Params));
	Ret.Virtual = Frame.Virtual;
	return Ret;
}

BOOL EnumSymCB(SYMBOL_INFO* SymInfo, unsigned long SymSize, void* UserContext)
{
	const char* Indent = (const char*)UserContext;
	PrintSymbolInfo(*SymInfo, Indent);
	return TRUE;
}

bool EnumLocalSymbols(const STACKFRAME64& CurFrame, const char* Indent = "")
{
	IMAGEHLP_STACK_FRAME Context = StackFrame64ToImageHlpStackFrame(CurFrame);
	if (!SymSetContext(GetCurrentProcess(), &Context, nullptr))
	{
		printf("SymSetContext failed: 0x%x\n", GetLastError());
		return false;
	}
	if (!SymEnumSymbols(GetCurrentProcess(), NULL, "*", &EnumSymCB, (void*)Indent))
	{
		printf("SymEnumSymbols failed: 0x%x\n", GetLastError());
		return false;
	}
	return true;
}

struct FUnwindInfoHeader
{
	unsigned char Version : 3;
	unsigned char Flags : 5;
	// In bytes
	unsigned char PrologSize;
	// Number of UNWIND_CODE's5554544
	unsigned char CodeCount;
	// If nonzero, a frame pointer is used
	// Value is the ID of the register used as FP
	unsigned char FrameReg : 4;
	// FP = RSP + 16 * FrameRegOffset when FP
	// was established
	unsigned char FrameRegOffset : 4;
};

struct FUnwindCode
{
	unsigned char OffsetInProlog;
	unsigned char UnwindOp : 4;
	unsigned char OpInfo : 4;
};

static inline const FUnwindCode* GetUnwindCodeArray(const FUnwindInfoHeader* UnwindInfo)
{
	return (const FUnwindCode*)((const char*)UnwindInfo + sizeof(FUnwindInfoHeader));
}

static inline const RUNTIME_FUNCTION* GetNextFuncEntry(const FUnwindInfoHeader* UnwindInfo)
{
	assert(UnwindInfo->Flags & UNW_FLAG_CHAININFO);
	const FUnwindCode* UnwindCode = GetUnwindCodeArray(UnwindInfo);
	return (const RUNTIME_FUNCTION*)&UnwindCode[(UnwindInfo->CodeCount + 1) & ~1];
}

static inline unsigned long GetExceptHandlerRVA(const FUnwindInfoHeader* UnwindInfo)
{
	assert(!(UnwindInfo->Flags & UNW_FLAG_CHAININFO)
		&& (UnwindInfo->Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)));
	const FUnwindCode* UnwindCode = GetUnwindCodeArray(UnwindInfo);
	return *(const unsigned long*)&UnwindCode[(UnwindInfo->CodeCount + 1) & ~1];
}

static inline std::string UnwindInfoFlags2StrInternal(int Flags, const char* Prefix = "")
{
	if (!Flags) return "";
	
	int LSBit = Flags & -Flags;
	Flags ^= LSBit;
	std::string s;
#define CASE_FLAG(X) case X: s = #X; break
	switch (LSBit)
	{
	CASE_FLAG(UNW_FLAG_EHANDLER);
	CASE_FLAG(UNW_FLAG_UHANDLER);
	CASE_FLAG(UNW_FLAG_CHAININFO);
	default: s = "?"; break;
	}
#undef CASE_FLAG
	return Prefix + s + UnwindInfoFlags2StrInternal(Flags, " | ");
}

static inline std::string UnwindInfoFlags2Str(int Flags)
{
	if (!Flags) return "UNW_FLAG_NHANDLER";
	return UnwindInfoFlags2StrInternal(Flags);
}

static inline const char* RegId2Str(int Id)
{
	switch (Id)
	{
	case 0: return "rax";
	case 1: return "rcx";
	case 2: return "rdx";
	case 3: return "rbx";
	case 4: return "rsp";
	case 5: return "rbp";
	case 6: return "rsi";
	case 7: return "rdi";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	default: return "?";
	}
}

static inline const char* XmmId2Str(int Id)
{
#define CASE_XMM(X) case X: return "xmm" #X
	switch (Id)
	{
	CASE_XMM(0);
	CASE_XMM(1);
	CASE_XMM(2);
	CASE_XMM(3);
	CASE_XMM(4);
	CASE_XMM(5);
	CASE_XMM(6);
	CASE_XMM(7);
	CASE_XMM(8);
	CASE_XMM(9);
	CASE_XMM(10);
	CASE_XMM(11);
	CASE_XMM(12);
	CASE_XMM(13);
	CASE_XMM(14);
	CASE_XMM(15);
	default: return "?";
	}
#undef CASE_XMM
}

static inline bool PrintUnwindCodeInternal(const FUnwindCode** OpPtr, const char* Indent = "")
{
	const FUnwindCode*& Op = *OpPtr;
	
	switch (Op->UnwindOp)
	{
	case UWOP_PUSH_NONVOL:
		printf("%s0x%x, %s, register=%s\n",
			Indent,
			Op->OffsetInProlog,
			"PUSH_NONVOL",
			RegId2Str(Op->OpInfo));
		++Op;
		break;
	case UWOP_ALLOC_LARGE:
		printf("%s0x%x, %s, size=%s0x%x\n",
			Indent,
			Op->OffsetInProlog,
			"ALLOC_LARGE",
			Op->OpInfo ? "" : "8 * ",
			Op->OpInfo ? *(unsigned long*)(Op + 1) : *(unsigned short*)(Op + 1));
		Op += Op->OpInfo + 2;
		break;
	case UWOP_ALLOC_SMALL:
		printf("%s0x%x, %s, size=8 * 0x%x + 8\n",
			Indent,
			Op->OffsetInProlog,
			"ALLOC_SMALL",
			Op->OpInfo);
		++Op;
		break;
	case UWOP_SET_FPREG:
		printf("%s0x%x, %s\n",
			Indent,
			Op->OffsetInProlog,
			"SET_FPREG");
		++Op;
		break;
	case UWOP_SAVE_NONVOL:
		printf("%s0x%x, %s, register=%s, stack offset=8 * 0x%x\n",
			Indent,
			Op->OffsetInProlog,
			"SAVE_NONVOL",
			RegId2Str(Op->OpInfo),
			*(unsigned short*)(Op + 1));
		Op += 2;
		break;
	case UWOP_SAVE_NONVOL_FAR:
		printf("%s0x%x, %s, register=%s, stack offset=0x%x\n",
			Indent,
			Op->OffsetInProlog,
			"SAVE_NONVOL_FAR",
			RegId2Str(Op->OpInfo),
			*(unsigned long*)(Op + 1));
		Op += 3;
		break;
	case UWOP_SAVE_XMM128:
		printf("%s0x%x, %s, register=%s, stack offset=16 * 0x%x\n",
			Indent,
			Op->OffsetInProlog,
			"SAVE_XMM128",
			XmmId2Str(Op->OpInfo),
			*(unsigned short*)(Op + 1));
		Op += 2;
		break;
	case UWOP_SAVE_XMM128_FAR:
		printf("%s0x%x, %s, register=%s, stack offset=0x%x\n",
			Indent,
			Op->OffsetInProlog,
			"SAVE_XMM128_FAR",
			XmmId2Str(Op->OpInfo),
			*(unsigned long*)(Op + 1));
		Op += 3;
		break;
	case UWOP_PUSH_MACHFRAME:
		printf("%s0x%x, %s, OpInfo=%d\n",
			Indent,
			Op->OffsetInProlog,
			"PUSH_MACHFRAME",
			Op->OpInfo);
		++Op;
		break;
	default:
		return false;
	}
	return true;
}

void PrintUnwindCode(const FUnwindCode* Code, int Num, const char* Indent = "")
{
	const auto* End = Code + Num;
	while (Code < End && PrintUnwindCodeInternal(&Code, Indent));
}

void PrintUnwindInfo(
	const FUnwindInfoHeader* UnwindInfo,
	unsigned long long ModuleBaseAddr,
	const char* Indent = "")
{
	printf(
		"%sUNWIND_INO {\n"
		"%s  Version=%d\n"
		"%s  Flags=%s\n"
		"%s  PrologSize=%d\n"
		"%s  CodeCount=%d\n"
		"%s  FrameReg=%d\n"
		"%s  FrameRegOffset=16 * 0x%x\n"
		"%s  Unwind code:\n",
		Indent,
		Indent, UnwindInfo->Version,
		Indent, UnwindInfoFlags2Str(UnwindInfo->Flags).c_str(),
		Indent, UnwindInfo->PrologSize,
		Indent, UnwindInfo->CodeCount,
		Indent, UnwindInfo->FrameReg,
		Indent, UnwindInfo->FrameRegOffset,
		Indent);
	std::string CodeIndent = "    ";
	CodeIndent += Indent;
	PrintUnwindCode(GetUnwindCodeArray(UnwindInfo), UnwindInfo->CodeCount, CodeIndent.c_str());
	if (!(UnwindInfo->Flags & UNW_FLAG_CHAININFO)
		&& (UnwindInfo->Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)))
	{
		SYMBOL_INFO_PACKAGE SymBuff = {};
		SYMBOL_INFO* SymInfo = &SymBuff.si;
		SymInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		SymInfo->MaxNameLen = MAX_SYM_NAME;
		const unsigned long HandlerRVA = GetExceptHandlerRVA(UnwindInfo);
		const char* HandlerName = "";
		if (SymFromAddr(GetCurrentProcess(), ModuleBaseAddr + HandlerRVA, 0, SymInfo))
		{
			HandlerName = SymInfo->Name;
		}
		printf("%s  Handler: 0x%x, %s\n", Indent, HandlerRVA, HandlerName);
	}
	printf("%s}\n", Indent);
}

void PrintFuncEntry(
	const RUNTIME_FUNCTION& FuncEntry,
	unsigned long long ModuleBaseAddr,
	const char* Indent = "")
{
	// Addresses are relative to module base address
	printf(
		"%sRUNTIME_FUNCTION {\n"
		"%s  BeginAddress=0x%x (0x%llx)\n"
		"%s  EndAddress=0x%x (0x%llx)\n"
		"%s  UnwindInfoAddress=0x%x (0x%llx)\n"
		"%s}\n",
		Indent,
		Indent, FuncEntry.BeginAddress, ModuleBaseAddr + FuncEntry.BeginAddress,
		Indent, FuncEntry.EndAddress, ModuleBaseAddr + FuncEntry.EndAddress,
		Indent, FuncEntry.UnwindInfoAddress, ModuleBaseAddr + FuncEntry.UnwindInfoAddress,
		Indent);
	const auto* UnwindInfo = (const FUnwindInfoHeader*)(ModuleBaseAddr + FuncEntry.UnwindInfoAddress);
	PrintUnwindInfo(UnwindInfo, ModuleBaseAddr, Indent);
	if (UnwindInfo->Flags & UNW_FLAG_CHAININFO)
	{
		PrintFuncEntry(*GetNextFuncEntry(UnwindInfo), ModuleBaseAddr, Indent);
	}
}

int main(int argc, const char** argv)
{
	// printf("%p, %p\n", &argc, &argv);
	InitDbgHelp();
	
	constexpr int MaxNumFrames = 100;
	STACKFRAME64* StackFrames = new STACKFRAME64[MaxNumFrames];
	CONTEXT* ThreadContexts = new CONTEXT[MaxNumFrames];
	int NumFrames;
	
	BackTraceStack(StackFrames, ThreadContexts, &NumFrames, MaxNumFrames);
	
	printf("Backtrace has %d stack frames\n", NumFrames);
	for (int Idx = 0; Idx < NumFrames; ++Idx)
	{
		const STACKFRAME64& Frame = StackFrames[Idx];
		const CONTEXT& Context = ThreadContexts[Idx];
		
		SYMBOL_INFO_PACKAGE SymBuff = {};
		SYMBOL_INFO* SymbolInfo = &SymBuff.si;
		SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		SymbolInfo->MaxNameLen = MAX_SYM_NAME;
		
		printf("--- Begin stack frame %d ---\n", Idx);
		PrintStackFrame64(Frame, "  ");
		if (SymFromAddr(GetCurrentProcess(), Frame.AddrPC.Offset, 0, SymbolInfo))
		{
			PrintSymbolInfo(*SymbolInfo, "  ");
			printf("  --- Begin local symbols ---\n");
			EnumLocalSymbols(Frame, "    ");
			printf("  --- End local symbols ---\n");
		}
		else
		{
			printf("  SymFromAddr failed: 0x%x\n", GetLastError());
		}
		
		const RUNTIME_FUNCTION* FuncEntry =
			(const RUNTIME_FUNCTION*)SymFunctionTableAccess64(
				GetCurrentProcess(),
				Frame.AddrPC.Offset);
		if (FuncEntry)
		{
			HMODULE ModuleHandle;
			if (GetModuleHandleEx(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
				GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				(LPCTSTR)Frame.AddrPC.Offset,
				&ModuleHandle))
			{
				printf("  --- Begin unwindinfo ---\n");
				PrintFuncEntry(*FuncEntry, (unsigned long long)ModuleHandle, "    ");
				printf("  --- End unwindinfo ---\n");
			}
			else
			{
				printf("  GetModuleHandleEx failed: 0x%x\n", GetLastError());
			}
		}
		else
		{
			printf("  SymFunctionTableAccess64 failed: 0x%x\n", GetLastError());
		}
		printf("--- End stack frame %d ---\n", Idx);
	}
	
	delete[] StackFrames;
	delete[] ThreadContexts;
	UninitDbgHelp();
	return 0;
}