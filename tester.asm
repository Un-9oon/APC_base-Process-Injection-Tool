; Project: Stealthy APC-Based Injection - Receiver
; File: tester.asm (Irvine32)
; =============================================================
INCLUDE Irvine32.inc
INCLUDELIB user32.lib 

; Prototypes for Alertable State
SleepEx             PROTO STDCALL, dwMilliseconds:DWORD, bAlertable:DWORD
GetCurrentProcessId PROTO STDCALL
GetCurrentThreadId  PROTO STDCALL
GetModuleHandleA    PROTO STDCALL, lpModuleName:PTR BYTE

.data
    msgTitle    BYTE "--- 32-bit APC Receiver (Alertable State) ---",0Ah,0
    msgPID      BYTE "[*] Target PID for Injector: ",0
    msgTID      BYTE "[*] Main Thread ID: ",0
    msgStatus   BYTE "[+] Status: user32.dll Loaded. Ready for APC.",0Ah,0
    msgWaiting  BYTE "[*] Thread entering alertable wait state...",0Ah,0
    msgAPCRecv  BYTE 0Ah,"[!!!] APC RECEIVED AND EXECUTED [!!!]",0Ah,0
    libName     BYTE "user32.dll",0 ; Necessary for MessageBoxA support
    pidVal      DWORD ?
    tidVal      DWORD ?
    apcReceived DWORD 0

.code

; APC Callback Marker (optional - for testing)
; This gets called when APC executes
APCCallback PROC STDCALL, dwParam:DWORD
    inc apcReceived
    ret
APCCallback ENDP

main PROC
    ; Load user32.dll forcefully to prevent shellcode crashes
    invoke GetModuleHandleA, OFFSET libName 
    
    call Clrscr
    mov  edx, OFFSET msgTitle
    call WriteString

    ; Display PID so you can enter it in the Injector
    invoke GetCurrentProcessId
    mov  pidVal, eax
    mov  edx, OFFSET msgPID
    call WriteString
    mov  eax, pidVal
    call WriteDec
    call Crlf

    ; Display Thread ID for tracking
    invoke GetCurrentThreadId
    mov  tidVal, eax
    mov  edx, OFFSET msgTID
    call WriteString
    mov  eax, tidVal
    call WriteDec
    call Crlf

    mov  edx, OFFSET msgStatus
    call WriteString
    
    mov  edx, OFFSET msgWaiting
    call WriteString

AlertLoop:
    ; Check if APC was received (optional feedback)
    mov eax, apcReceived
    test eax, eax
    jz skip_apc_msg
    mov edx, OFFSET msgAPCRecv
    call WriteString
    mov apcReceived, 0
skip_apc_msg:

    ; Section 3.1: Thread enters alertable state (bAlertable=1)
    ; This is the 'handshake' that allows APC to execute
    invoke SleepEx, 100, 1 
    jmp  AlertLoop
main ENDP
END main
