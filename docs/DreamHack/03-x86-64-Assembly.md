## x86-64 Assembly

- [x86-64 Assembly](#x86-64-assembly)
  - [Basic Structure](#basic-structure)
    - [Opcode](#opcode)
    - [Operands](#operands)
    - [Data Movement](#data-movement)
    - [Arithmetic Operations](#arithmetic-operations)
    - [Logical Operations](#logical-operations)
    - [Comparison and Testing](#comparison-and-testing)
    - [Branching Instructions](#branching-instructions)

I thought writing down all of x86-64 reference sheet is kinda pointless, so I'll just link down some useful references.

- [CS107 x86-64 Reference Sheet from Stanford University](https://web.stanford.edu/class/cs107/resources/x86-64-reference.pdf) - for the sake of your sanity, you're better off checking this
- [Félix Cloutier's x86 and amd64 instruction reference](https://www.felixcloutier.com/x86/)
- [Intel® 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)

---

### Basic Structure

x64's code consist of an instruction (operation code, opcode), which is equivalent to a verb, and an operand, which is equivalent to an object.

```x86asm
mov eax, 3
; opcode / operand1/ operand2
; Move / to eax / the value 3
```

#### Opcode

x86 has a very large number of instructions, so I'll only cover 21 of the most common ones:

| Category | Instructions |
|----------|-------------|
| Data Transfer | `mov`, `lea` |
| Arithmetic | `inc`, `dec`, `add`, `sub` |
| Logical | `and`, `or`, `xor`, `not` |
| Comparison | `cmp`, `test` |
| Branch | `jmp`, `je`, `jg` |
| Stack | `push`, `pop` |
| Procedure | `call`, `ret`, `leave` |
| System Call | `syscall` |

#### Operands

Operands in x86-64 assembly can be one of three types:

- **Immediate value**: Direct constants (e.g., `42`, `0x1337`)
- **Register**: CPU registers that hold values
- **Memory**: References to data in memory

Memory operands use square brackets `[]` and typically include a size directive (TYPE PTR). The size indicates how many bytes should be accessed:

| Size Directive | Bytes | Bits | C Equivalent |
|----------------|-------|------|--------------|
| BYTE PTR       | 1     | 8    | `char`       |
| WORD PTR       | 2     | 16   | `short`      |
| DWORD PTR      | 4     | 32   | `int`        |
| QWORD PTR      | 8     | 64   | `long long`  |

Examples:
```x86asm
mov eax, 42            ; Immediate value
mov rbx, rax           ; Register
mov DWORD PTR [rsp], 1 ; Memory (32-bit)
```

> [!NOTE]
> [comparison between Intel and AT&T syntax for x86 assembly](https://imada.sdu.dk/u/kslarsen/dm546/Material/IntelnATT.htm)


#### Data Movement

`mov dst, src`: Copies the value from source to destination

| Example | Description |
|---------|-------------|
| `mov rdi, rsi` | Copies the value from register `rsi` to register `rdi` |
| `mov QWORD PTR [rdi], rsi` | Copies the value from register `rsi` to the memory address pointed to by `rdi` |
| `mov QWORD PTR [rdi+8*rcx], rsi` | Copies the value from register `rsi` to the memory address calculated by `rdi+8*rcx` |
| `lea rsi, [rbx+8*rcx]` | Stores the address calculated by `rbx+8*rcx` into register `rsi` (without accessing memory) |

Unlike `mov`, the `lea` instruction calculates memory addresses **without actually accessing memory**, making it useful for pointer arithmetic and efficient address calculations.

#### Arithmetic Operations

Arithmetic operation instructions perform basic mathematical operations like <u>addition</u>, <u>subtraction</u>, <u>multiplication</u>, and <u>division</u>. Here we'll focus on the most common ones:

`add dst, src`: Adds the value of src to dst

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `add eax, 3` | Adds 3 to the value in register `eax` | `eax += 3;` |
| `add ax, WORD PTR [rdi]` | Adds the 16-bit value at memory address in `rdi` to `ax` | `ax += *(short*)rdi;` |

`sub dst, src`: Subtracts the value of src from dst

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `sub eax, 3` | Subtracts 3 from the value in register `eax` | `eax -= 3;` |
| `sub ax, WORD PTR [rdi]` | Subtracts the 16-bit value at memory address in `rdi` from `ax` | `ax -= *(short*)rdi;` |

`inc op`: Increases the value of op by 1

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `inc eax` | Increments the value in register `eax` by 1 | `eax++;` |

`dec op`: Decreases the value of op by 1

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `dec eax` | Decrements the value in register `eax` by 1 | `eax--;` |

#### Logical Operations

Logical operations perform bitwise manipulation of data, which is useful for masking bits, setting/clearing flags, and other low-level operations.

`and dst, src`: Performs a bitwise AND between src and dst, storing the result in dst

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `and eax, 0xF` | Performs bitwise AND between `eax` and `0xF` (keeps only the lowest 4 bits) | `eax &= 0xF;` |
| `and al, BYTE PTR [rdi]` | Performs bitwise AND between `al` and the byte at memory address in `rdi` | `al &= *(char*)rdi;` |

`or dst, src`: Performs a bitwise OR between src and dst, storing the result in dst

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `or eax, 0x80000000` | Sets the highest bit in `eax` | `eax |= 0x80000000;` |
| `or bx, WORD PTR [rsi]` | Performs bitwise OR between `bx` and the word at memory address in `rsi` | `bx |= *(short*)rsi;` |

`xor dst, src`: Performs a bitwise XOR between src and dst, storing the result in dst

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `xor eax, eax` | Clears `eax` to zero (common idiom, more efficient than `mov eax, 0`) | `eax ^= eax;` or `eax = 0;` |
| `xor rax, QWORD PTR [rdi]` | Performs bitwise XOR between `rax` and the qword at memory address in `rdi` | `rax ^= *(long long*)rdi;` |

`not op`: Performs a bitwise NOT (inverts all bits) of op

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `not eax` | Inverts all bits in `eax` | `eax = ~eax;` |

#### Comparison and Testing

Comparison instructions are used to set flags in the processor's status register, which can then be used by conditional branch instructions.

`cmp op1, op2`: Compares two operands by performing (op1 - op2) and setting flags based on the result

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `cmp eax, 0` | Compares `eax` with 0 | `eax - 0` (result not stored) |
| `cmp bx, WORD PTR [rdi]` | Compares `bx` with the word at memory address in `rdi` | `bx - *(short*)rdi` (result not stored) |

`test op1, op2`: Performs a bitwise AND between two operands, setting flags without storing the result

| Example | Description | C Equivalent |
|---------|-------------|--------------|
| `test eax, eax` | Tests if `eax` is zero | `eax & eax` (result not stored) |
| `test al, 0x80` | Tests if the highest bit of `al` is set | `al & 0x80` (result not stored) |

#### Branching Instructions

Branch instructions control program flow by changing the instruction pointer based on conditions.

`jmp target`: Unconditional jump to target address

| Example | Description |
|---------|-------------|
| `jmp label` | Jumps to the specified label |
| `jmp rax` | Jumps to the address stored in `rax` |

`je/jz target`: Jump if equal/zero (if ZF flag is set)

| Example | Description | Typical Usage |
|---------|-------------|---------------|
| `je label` | Jumps to label if the previous comparison showed equality | `if (a == b) goto label;` |

`jne/jnz target`: Jump if not equal/not zero (if ZF flag is not set)

| Example | Description | Typical Usage |
|---------|-------------|---------------|
| `jne label` | Jumps to label if the previous comparison showed inequality | `if (a != b) goto label;` |

`jg/jnle target`: Jump if greater/not less or equal (signed comparison)

| Example | Description | Typical Usage |
|---------|-------------|---------------|
| `jg label` | Jumps to label if first operand was greater than second | `if (a > b) goto label;` |

