# stack_unwind_experiment
Some experiment code to understand x64 ABI on MSVC Windows<br>
> cl /Zi /EHsc stack_unwind.cpp<br>
> dumpbin /unwindinfo stack_unwind.exe > unwindinfo.txt<br>
> dumpbin /disasm stack_unwind.exe > disasm.txt<br>
> stack_unwind > tmp.txt<br>
