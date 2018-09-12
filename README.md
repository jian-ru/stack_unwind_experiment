# stack_unwind_experiment
Some experiment code to understand x64 ABI on MSVC Windows
> cl /Zi /EHsc stack_unwind.cpp
> dumpbin /unwindinfo stack_unwind.exe > unwindinfo.txt
> dumpbin /disasm stack_unwind.exe > disasm.txt
> stack_unwind > tmp.txt
