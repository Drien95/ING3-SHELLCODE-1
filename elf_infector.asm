section .data
	file_path db "/tmp/ls", 0	; j'effectue un test sur mon fichier ls copie dans /tmp
	buffer_size equ 10000		;  taille buffer
	
	; open msg syscall
	error_open_msg db "Erreur lors de l'ouverture du fichier", 0xA
	error_open_msg_len equ $ - error_open_msg
	ok_open_msg db "Ouverture correcte du fichier", 0xA
	ok_open_msg_len equ $ - ok_open_msg

	; read msg syscall
	error_read_msg db "Erreur lors de la lecture du fichier", 0xA
	error_read_msg_len equ $ - error_read_msg
	ok_read_msg db "Lecture correcte du fichier", 0xA
	ok_read_msg_len equ $ - ok_read_msg

section .bss
	buffer resb buffer_size		; Je reserve un espace memoire pour mon elf

section .text

global _start

_start:
	;syscall open, pour l'ouverture de notre fichier elf
	mov rax, 2			; syscall open
	lea rdi, [rel file_path]	; path de notre elf
	mov rsi, 0			; O_RDONLY
	syscall
	test rax, rax			; Check si le file est OK (rax==0)
	js _error_open			; Gestion d'erreur pour open
	mov r13, rax			; Si OK alors on met le fd dans r13 en attendant le syscall print
	call _ok_open	
	
	; Lecture du fichier
	; syscall read				
	mov rax, 0			; read(
	mov rdi, r13			; int fd,
	mov rsi, buffer			; void buf*, 	
	mov rdx, buffer_size		; size_t count
	syscall				;)
	;	gestion erreur sys_read
	test rax, rax
	js _error_read
	call _ok_read


	call _exit


_ok_read:
	lea rsi,  [rel ok_read_msg]
	mov rdx, ok_read_msg_len
	call _print_msg
	ret

_error_read:
	lea rsi, [rel error_read_msg]
	mov rdx, error_read_msg_len
	call _print_msg
	call _exit	

_ok_open:
	lea rsi, [rel ok_open_msg]
	mov rdx, ok_open_msg_len
	call _print_msg
	ret

_error_open:
	; syscall pour exit + petit message
	lea rsi, [rel error_open_msg]
	mov rdx, error_open_msg_len
	call _print_msg
	call _exit

_print_msg:
	mov rax, 1
	mov rdi, 1
	syscall
	ret

_exit:
	mov rax, 60
	xor rdi, rdi
	syscall
