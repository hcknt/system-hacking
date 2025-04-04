## x86-64 Calling Convention

- [x86-64 Calling Convention](#x86-64-calling-convention)
  - [SYSV](#sysv)
    - [Passing Arguments](#passing-arguments)
    - [Saving Return Address](#saving-return-address)
    - [Saving Stack Frame](#saving-stack-frame)
    - [Assigning Stack Frame](#assigning-stack-frame)
    - [Returning Value](#returning-value)
  - [cdecl](#cdecl)

### SYSV

Linux is based on the **SYSTEM V (SYSV) Application Binary Interface (ABI)**, which defines the <u>ELF format</u>, <u>linking methods</u>, <u>function calling conventions</u>, and more. When using the `file` command, you can often see SYSV-related strings in the output.

```console
$ file ncurogue
ncurogue: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked ...
```

The SYSV calling convention defines these rules:

1. The first 6 arguments are passed in registers in the following order: `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`. Any additional arguments are passed on the **stack**.
2. The caller is responsible for cleaning up the stack space used for passing arguments.
3. The return value of a function is stored in the `RAX` register.

Now, let's examine these concepts through dynamic analysis with GDB.

```c
// Name: sysv.c

#define ull unsigned long long

ull callee(ull a1, int a2, int a3, int a4, int a5, int a6, int a7) {
  ull ret = a1 + a2 + a3 + a4 + a5 + a6 + a7;
  return ret;
}

void caller() { callee(123456789123456789, 2, 3, 4, 5, 6, 7); }

int main() { caller(); }
```

Compile with,

```console
$ gcc -fno-asynchronous-unwind-tables -masm=intel -fno-omit-frame-pointer -o sysv sysv.c -fno-pic -O0
```

#### Passing Arguments

First, set a breakpoint on `caller`.

```nasm
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x555555555175 <caller+4>     push   7
   0x555555555177 <caller+6>     mov    r9d, 6                     R9D => 6
   0x55555555517d <caller+12>    mov    r8d, 5                     R8D => 5
   0x555555555183 <caller+18>    mov    ecx, 4                     ECX => 4
   0x555555555188 <caller+23>    mov    edx, 3                     EDX => 3
   0x55555555518d <caller+28>    mov    esi, 2                     ESI => 2
   0x555555555192 <caller+33>    movabs rax, 0x1b69b4bacd05f15     RAX => 0x1b69b4bacd05f15
   0x55555555519c <caller+43>    mov    rdi, rax                   RDI => 0x1b69b4bacd05f15
   0x55555555519f <caller+46>    call   callee                      <callee>
```

We can see that the disassembly confirms the SYSV calling convention:
- The first 6 arguments are loaded into registers **in order**.
- The 7th argument is pushed onto the stack with `push 7`.
- The large first argument (123456789123456789) is first loaded into `RAX` and then moved to `RDI`, which is the register designated for the first argument.

```nasm
 ► 0x55555555519f <caller+46>    call   callee                      <callee>
        rdi: 0x1b69b4bacd05f15
        rsi: 2
        rdx: 3
        rcx: 4
```

#### Saving Return Address

When we step into the `callee` function, we can see that `0x5555555551a4` is saved as the **return address** on the stack. This address corresponds to the instruction immediately following the `call callee` instruction (caller+51).

```nasm
──────────────────────[ STACK ]──────────────────────
00:0000│ rsp 0x7fffffffd8a0 —▸ 0x5555555551a4 (caller+51) ◂— add rsp, 8
```

This demonstrates how the `call` instruction automatically pushes the return address (the address of the next instruction after the call) onto the stack before transferring control to the called function. When the called function completes, the `ret` instruction pops this address from the stack and jumps to it, returning execution to the instruction right after the original call.

#### Saving Stack Frame

When we examine the `callee` function, we can see the function prologue:

```console
pwndbg> x/5i $rip
=> 0x555555555119 <callee>:     push   rbp
   0x55555555511a <callee+1>:   mov    rbp,rsp
```

`push rbp` saves the current base pointer (RBP) value on the stack. This preserves the caller's frame pointer so it can be restored later.

#### Assigning Stack Frame

After saving the previous frame pointer, the instruction `mov rbp, rsp` sets the new base pointer (RBP) to point to the current stack pointer (RSP). This establishes the top boundary of the new stack frame.

Typically, the next step would be to reserve space for local variables by subtracting from RSP (like `sub rsp, N` where N is the space needed). However, in our `callee` function, we don't see this operation because this particular function doesn't use any local variables that require stack space allocation.

If the function did have local variables, we would see something like:
```nasm
push rbp
mov rbp, rsp
```

The space between `RBP` and `RSP` becomes the **new stack frame**, where:
- `RBP` points to the saved **previous frame pointer**
- Local variables are accessed at negative offsets from `RBP`
- Function parameters are accessed at positive offsets from `RBP`

However, the `callee` function doesn't use local variables, so it doesn't create a new stack frame.

```console
pwndbg> print $rbp
$4 = (void *) 0x7fffffffd898
pwndbg> print $rsp
$5 = (void *) 0x7fffffffd898
```

#### Returning Value

After all calculations are complete and the function reaches its epilogue (closing section), we can see the return value being placed in the `RAX` register.

```nasm
   0x55555555516b <callee+82>    mov    rax, qword ptr [rbp - 8]     RAX, [0x7fffffffd890] => 0x1b69b4bacd05f30
   0x55555555516f <callee+86>    pop    rbp                          RBP => 0x7fffffffd8b0
 ► 0x555555555170 <callee+87>    ret                                <caller+51>
    ↓
   0x5555555551a4 <caller+51>    add    rsp, 8     RSP => 0x7fffffffd8b0 (0x7fffffffd8a8 + 0x8)
```

The function first loads the calculated return value into `RAX`, then restores the previous frame pointer with `pop rbp`, and finally returns to the caller with the `ret` instruction.

### cdecl

Due to the limited number of registers in x86, cdecl passes function arguments through the **stack**.

When passing arguments via the stack in cdecl:
1. Arguments are pushed onto the stack in **reverse order** - the last argument is pushed first, and the first argument is pushed last.
2. The return value is stored in the `EAX`.

```c
// Name: cdecl.c
// Compile: gcc -fno-asynchronous-unwind-tables -nostdlib -masm=intel \
//          -fomit-frame-pointer -S cdecl.c -w -m32 -fno-pic -O0

void __attribute__((cdecl)) callee(int a1, int a2){
}

void caller(){
   callee(1, 2);
}
```

```nasm
	.file	"cdcel.c"
	.intel_syntax noprefix
	.text
	.globl	callee
	.type	callee, @function
callee:
	nop
	ret
	.size	callee, .-callee
	.globl	caller
	.type	caller, @function
caller:
	push	2
	push	1 ; order reversed!
	call	callee
	add	esp, 8
	nop
	ret
	.size	caller, .-caller
	.ident	"GCC: (GNU) 14.2.1 20250207"
	.section	.note.GNU-stack,"",@progbits
```

