import ctypes

# Paste your shellcode here as a Python bytes string
# Example: shellcode = b"\x90\x90\x90\xcc"
shellcode = b""

if not shellcode:
    print("[!] Error: No shellcode provided. Add your shellcode bytes to the 'shellcode' variable.")
    exit(1)

shellcode = bytearray(shellcode)

  # Allocate memory
ptr = ctypes.windll.kernel32.VirtualAlloc(
      ctypes.c_int(0),
      ctypes.c_int(len(shellcode)),
      ctypes.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
      ctypes.c_int(0x40)      # PAGE_EXECUTE_READWRITE
  )

  # Copy shellcode to allocated memory
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
      ctypes.c_int(ptr),
      buf,
      ctypes.c_int(len(shellcode))
  )

print("Shellcode located at address %s" % hex(ptr))
print("Shellcode size: %d bytes" % len(shellcode))
#raw_input("...PRESS ENTER TO EXECUTE SHELLCODE...") # python 2
input("...PRESS ENTER TO EXECUTE SHELLCODE...") # python 3

  # Create thread to execute shellcode
ht = ctypes.windll.kernel32.CreateThread(
      ctypes.c_int(0),
      ctypes.c_int(0),
      ctypes.c_int(ptr),
      ctypes.c_int(0),
      ctypes.c_int(0),
      ctypes.pointer(ctypes.c_int(0))
  )

  # Wait for thread to finish
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
