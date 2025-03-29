## Linux Memory Layout

- [Linux Memory Layout](#linux-memory-layout)
  - [Segments](#segments)
    - [Code Segment](#code-segment)
    - [Data Segment](#data-segment)
    - [BSS Segment](#bss-segment)
    - [Stack Segment](#stack-segment)
    - [Heap Segment](#heap-segment)

The virtual memory space of a Linux process is divided into distinct regions:

| Segment | Purpose | Access Permissions | Growth Direction |
|---------|---------|-------------------|-----------------|
| Text/Code | Executable program instructions | Read-only, Execute | Fixed size |
| Data | Initialized global and static variables | Read-write | Fixed size |
| BSS | Uninitialized global and static variables (zero-initialized) | Read-write | Fixed size |
| Heap | Dynamic memory allocation (malloc, new) | Read-write | Grows upward (higher addresses) |
| Stack | Function calls, local variables, return addresses | Read-write | Grows downward (lower addresses) |
| Memory Mapped | Shared libraries, file mappings, shared memory | Varies (can be configured) | Fixed size per mapping |

Common memory corruption vulnerabilities include **Stack Buffer Overflow**, **Format String Bug**, **Use After Free**, and **Double Free Bug**, each targeting different regions of memory.

### Segments

Linux divides a process' memory into five main **segments**, following:

- **Process**
  - **Code**: int foo() {...}
  - **Data**: int initialized_global = 0;
  - **BSS**: int uninitialized_global;
  - **Stack**: int foo() { int local = 0; }
  - **Heap**: int *ptr = malloc(4);

The advantage of having this kind of structure is that an appropriate permission can be granted to each segment per its usage. There are <u>read</u>, <u>write</u>, and <u>execute</u>.

#### Code Segment

**Code segment** (a.k.a. **text segment**) contains the executable machine code. It has read and execute permissions but is typically non-writable to prevent code injection attacks.

Here's what the machine code for a `main()` function looks like:

```c
int main() { return 31337; }

/* 0000000000001119 <main>:
    1119:       55                      push   %rbp
    111a:       48 89 e5                mov    %rsp,%rbp
    111d:       b8 69 7a 00 00          mov    $0x7a69,%eax
    1122:       5d                      pop    %rbp
    1123:       c3                      ret */
```

#### Data Segment

**Data segment** contains <u>initialized global</u> and <u>static variables</u> whose values are determined at compile time. This segment is typically granted read permission by default, as the CPU needs to access these values. Depending on whether the data is marked as constant, portions of this segment may also have write permission (for variables) or be read-only (for constants).

```c
int data_num = 31337;                       // data
char data_rwstr[] = "writable_data";        // data
const char data_rostr[] = "readonly_data";  // rodata
char *str_ptr = "readonly";  // str_ptr in data, string in rodata

int main() { ... }
```

#### BSS Segment

**BSS segment** (Block Started By Symbol Segment) contains <u>uninitialized global and static variables</u>. All memory in this segment is automatically initialized to **zero** when the program starts, which saves space in the executable file since these zero values don't need to be stored explicitly.

```c
int bss_data;
static int global_static; // goes in BSS

int main() {
  printf("%d\n", bss_data);  // 0
  static int local_static; // also goes in BSS
  return 0;
}
```

#### Stack Segment

The **Stack Segment** is a region of memory that manages <u>function execution</u> context. It stores <u>local variables</u>, <u>function parameters</u>, <u>return addresses</u>, and <u>saved registers</u>. 

The stack operates on a Last-In-First-Out (LIFO) principle, with each function call creating a "stack frame" that contains <u>all the data needed for that function's execution</u>. When a function completes, its stack frame is removed, automatically cleaning up local variables and restoring the execution context to the calling function.

The stack grows downward in memory (toward lower addresses) as new functions are called, and shrinks as functions return. This dynamic growth and automatic memory management make the stack ideal for tracking program execution flow, though it comes with limited size constraints compared to the heap.

#### Heap Segment

The **Heap Segment** provides memory for <u>dynamic allocation</u> during program execution. Unlike the stack, heap memory is managed explicitly by the programmer through functions like `malloc()`, `calloc()`, and `free()` in C.

The heap grows upward (toward higher addresses) while the stack grows downward, maximizing available memory space between them. This opposite growth direction helps **prevent collisions** between these two dynamic memory regions.

```c
int main() {
  int *heap_data_ptr = malloc(sizeof(int));  // Allocates memory on the heap
  *heap_data_ptr = 31337;                    // Writes to heap memory
  printf("%d\n", *heap_data_ptr);            // Reads from heap memory
  free(heap_data_ptr);                       // Releases heap memory
  return 0;
}
```