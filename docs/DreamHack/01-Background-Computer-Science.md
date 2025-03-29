## Computer Architecture and Instruction Set Architecture

- [Computer Architecture and Instruction Set Architecture](#computer-architecture-and-instruction-set-architecture)
  - [Subdivisions of Computer Architecture](#subdivisions-of-computer-architecture)
  - [Von Neumann Architecture](#von-neumann-architecture)
    - [Central Processing Unit](#central-processing-unit)
    - [Memory](#memory)
    - [Bus](#bus)
  - [Instruction Set Architecture](#instruction-set-architecture)
  - [x86-64 Architecture](#x86-64-architecture)
    - [Bit Architecture and Word Size](#bit-architecture-and-word-size)
    - [Advantages of 64-bit Architecture](#advantages-of-64-bit-architecture)
  - [x86-64 Architecture: Registers](#x86-64-architecture-registers)
    - [General-Purpose Registers](#general-purpose-registers)
    - [Segment Registers](#segment-registers)
    - [Instruction Pointer Register](#instruction-pointer-register)
    - [Flag Register](#flag-register)
    - [Examining Flags Using GDB](#examining-flags-using-gdb)
  - [Register Compatibility](#register-compatibility)

**Computer Architecture** refers to how the features of HW and SW are designed and how they are organized. It includes the design of computer's functional architecture, instruction set architecture, microarchitecture, and other HW and computing methods.

### Subdivisions of Computer Architecture

- Designing a computer's functional architecture
  - Von Neumann architecture: Most PCs and servers, uses shared memory for instructions and data
  - Harvard architecture: DSPs and microcontrollers, separate instruction and data memory
  - Modified Harvard architecture: ARM Cortex-M, separate caches but shared main memory
- Instruction Set architecture
  - x86, x86-64(a.k.a. x64, AMD64, Intel 64): Intel Core i7, AMD Ryzen, CISC with variable-length instructions
  - ARM: Apple M1/M2, Qualcomm Snapdragon, RISC architecture for mobile/embedded devices
  - MIPS: PlayStation 1-2, Nintendo 64, RISC with fixed 32-bit instructions
  - AVR: Arduino microcontrollers, 8-bit RISC for embedded systems
- Microarchitecture
  - Cache design: Multi-level caches (L1/L2/L3) with different access speeds
  - Pipelining: Breaking instruction execution into stages for parallelism
  - Superscalar: AMD Zen, Intel Core, executing multiple instructions simultaneously
  - Branch prediction: Predicts which path conditional code will take to avoid pipeline stalls
  - Non-sequential instruction processing: Out-of-order execution optimizing instruction flow
- Hardware and computing methodology
  - Direct memory access: Allows peripherals to access memory independently of CPU

This repo will concentrate on studying the **Von neumann architecture** and **x86-64**.

### Von Neumann Architecture

Von Neumann Architecture contains three core functionalities: <u>compute</u>, <u>control</u>, and <u>store</u>. Modern computers use **central processing units(CPUs)** for computation and control, **memory** for storage, and electronic pathways called **bus** to exchange data or control signals between devices.

<a title="Kapooht, CC BY-SA 3.0 &lt;https://creativecommons.org/licenses/by-sa/3.0&gt;, via Wikimedia Commons" href="https://commons.wikimedia.org/wiki/File:Von_Neumann_Architecture.svg"><img width="" alt="Von Neumann Architecture" src="https://upload.wikimedia.org/wikipedia/commons/thumb/e/e5/Von_Neumann_Architecture.svg/510px-Von_Neumann_Architecture.svg.png?20130427233915"></a>

<small><a href="https://commons.wikimedia.org/wiki/File:Von_Neumann_Architecture.svg">Kapooht</a>, <a href="https://creativecommons.org/licenses/by-sa/3.0">CC BY-SA 3.0</a>, via Wikimedia Commons</small>

#### Central Processing Unit

CPU is the brain of the computer, handling computation and system management. It consists of the Arithmetic Logic Unit (ALU) for mathematical operations, Control Unit for directing operations, and Registers for storing data within the CPU.

#### Memory

Memory stores data for computer operations and is divided into **main memory** (RAM) for temporary program execution data, and **auxiliary memory** (HDD, SSD) for long-term storage of operating systems and programs.

#### Bus

Bus provides pathways for signals between computer components, including data bus (transfers data), address bus (specifies memory locations), and control bus (manages read/write operations).

### Instruction Set Architecture

Instruction Set Architecture (ISA) is the set of commands a CPU can understand and execute. Programs are written in machine language that the CPU processes. We'll focus specifically on the x86-64 architecture.

### x86-64 Architecture

x86-64 is a 64-bit extension of Intel's 32-bit architecture, first developed by AMD in 1999 and later adopted universally (including by Intel). Most modern personal computers use CPUs based on this architecture.

#### Bit Architecture and Word Size

In computing, the "bit" number (32-bit, 64-bit) refers to the CPU's word size - the amount of data it can process at once. This determines the CPU's computational capabilities, register capacity, and bus bandwidth.

#### Advantages of 64-bit Architecture

The primary advantage of 64-bit over 32-bit architecture is expanded memory addressing. While 32-bit systems are limited to 4GB of virtual memory, 64-bit systems can theoretically address up to 16 exabytes (16,777,216 terabytes), ensuring sufficient memory resources for even the most demanding applications.

### x86-64 Architecture: Registers

Registers are high-speed storage locations within the CPU. In x86-64, registers include:

#### General-Purpose Registers
64-bit registers that store data, addresses, or calculation results:

| Register | Name | Primary Use |
|----------|------|-------------|
| `rax` | Accumulator Register | Return value of a function |
| `rbx` | Base Register | No primary use on x64 |
| `rcx` | Counter Register | Loop count for loop statements, or execution count for various operations |
| `rdx` | Data Register | No primary use on x64 |
| `rsi` | Source Index | Pointer to the source when moving data |
| `rdi` | Destination Index | Pointer to the destination when moving data |
| `rsp` | Stack Pointer | Pointer to the location of the stack in use |
| `rbp` | Stack Base Pointer | Pointer to the bottom of the stack |

#### Segment Registers
16-bit registers with specialized purposes:
- `cs`, `ds`, `ss`: Code, data, and stack segment pointers
- `es`, `fs`, `gs`: Additional segment registers used by the OS

While segment registers were crucial in older architectures for expanding addressable memory, their role has diminished in x86-64 with its much larger address space.

#### Instruction Pointer Register

The instruction pointer register (`RIP`) is an 8-byte register that indicates which instruction the CPU should execute next in the program's machine code sequence.

#### Flag Register

The flag register (`RFLAGS`) is a 64-bit register that stores the **processor's current state**. Though it can support up to 64 flags, only about 20 bits are used. The most important flags include:

| Flag | Meaning |
|------|---------|
| CF (Carry Flag) | Set when an unsigned operation result exceeds the bit range |
| ZF (Zero Flag) | Set when an operation result is zero |
| SF (Sign Flag) | Set when an operation result is negative |
| OF (Overflow Flag) | Set when a signed operation result exceeds the bit range |

#### Examining Flags Using GDB

We can see the status of the flags in running program easily with GDB by using the `info registers` command. This displays which flags are currently set:

```console
pwndbg> info registers eflags
eflags         0x246               [ PF ZF IF ]
```

In this example, the Parity Flag (PF), Zero Flag (ZF), and Interrupt Flag (IF) are set, while others like the Carry Flag (CF) and Sign Flag (SF) are clear.

### Register Compatibility

The x86-64 architecture maintains backward compatibility with earlier instruction sets (IA-32 and IA-16). Each register can be accessed in different sizes:

| 64-bit (x86-64) | 32-bit (IA-32) | 16-bit (IA-16) | High 8-bit | Low 8-bit |
|-----------------|----------------|----------------|------------|-----------|
| `rax` | `eax` | `ax` | `ah` | `al` |
| `rbx` | `ebx` | `bx` | `bh` | `bl` |
| `rcx` | `ecx` | `cx` | `ch` | `cl` |
| `rdx` | `edx` | `dx` | `dh` | `dl` |
| `rsi` | `esi` | `si` | - | `sil` |
| `rdi` | `edi` | `di` | - | `dil` |
| `rsp` | `esp` | `sp` | - | `spl` |
| `rbp` | `ebp` | `bp` | - | `bpl` |