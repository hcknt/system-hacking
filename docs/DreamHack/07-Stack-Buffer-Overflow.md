## Stack Buffer Overflow

- [Stack Buffer Overflow](#stack-buffer-overflow)
  - [Buffer Overflow](#buffer-overflow)
    - [Buffer](#buffer)
    - [Buffer Overflow](#buffer-overflow-1)
    - [Example - Manipulating Important Data](#example---manipulating-important-data)
    - [Example - Data Leakage](#example---data-leakage)
    - [Example - Return Address Buffer Overflow](#example---return-address-buffer-overflow)

### Buffer Overflow

**Stack buffer overflow** refers to an overflow that occurs in a buffer on the stack.

#### Buffer

In computer science, a buffer traditionally refers to "a temporary storage area where data is held before being transferred to its destination."

In modern usage, this definition has broadened, and now any unit that can store data might be called a buffer. Local variables on the stack are called <u>stack buffers</u>, while memory regions allocated on the heap are called <u>heap buffers</u>.

#### Buffer Overflow

Buffer overflow literally means that a buffer is overflowing. For example, if 20 bytes of data are placed into a `char array[10]`, a buffer overflow occurs.

#### Example - Manipulating Important Data

```c
// Name: sbof_auth.c
// Compile: gcc -o sbof_auth sbof_auth.c -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_auth(char *password) {
    int auth = 0;
    char temp[16];
    
    strncpy(temp, password, strlen(password));
    
    if(!strcmp(temp, "SECRET_PASSWORD"))
        auth = 1;
    
    return auth;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: ./sbof_auth ADMIN_PASSWORD\n");
        exit(-1);
    }

    if (check_auth(argv[1]))
        printf("Hello Admin!\n");
    else
        printf("Access Denied!\n");
}
```

The `check_auth` function copies the input password into a 16-byte `temp` buffer and compares it with the string `"SECRET_PASSWORD"`. However, when using `strncpy`, it copies as much as `strlen(password)`, which means if a string longer than 16 bytes is passed, all of it will be copied, **causing a stack overflow**.

Since `int auth` exists after `char temp[16]` in stack memory, we can overflow the `temp` buffer to change the value of `auth` to a non-zero value. In this case, `if (check_auth(argv[1]))` will always evaluate to true because it's not `2`.

| Higher addresses |                                                    |
| ---------------- | -------------------------------------------------- |
| int auth         | $\rightarrow$ Overwritten if temp buffer overflows |
| char temp[16]    | $\rightarrow$ Buffer that can overflow             |
| Lower addresses  |                                                    |

#### Example - Data Leakage

In C, normal strings are terminated with a NULL byte. If we cause a buffer overflow that removes all that things between buffers, it's possible to output data from other buffers as well.

```c
// Name: sbof_leak.c
// Compile: gcc -o sbof_leak sbof_leak.c -fno-stack-protector
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    char secret[16] = "secret message";
    char barrier[4] = {}; // filled with null bytes
    char name[8] = {};
    memset(barrier, 0, 4);
    printf("Your name: ");
    read(0, name, 12);
    printf("Your name is %s.", name);
}
```

#### Example - Return Address Buffer Overflow

Looking back at [Calling Conventions](/docs/DreamHack/06-Calling-Convention.md), when a function is called, the <u>return address</u> is pushed onto the stack. When the function ends, this address is retrieved to **return to the original location**. We can manipulate this return address using a stack buffer overflow.

```c
// Name: sbof_ret_overwrite.c
// Compile: gcc -o sbof_ret_overwrite sbof_ret_overwrite.c -fno-stack-protector
#include <stdio.h>
#include <unistd.h>

void win() {
    printf("You won!\n");
}

int main(void) {
    char buf[8];
    printf("Overwrite return address with %p:\n", &win);
    read(0, buf, 32);
    return 0;
}
```

In this code, the address of `win()` is printed and 32 bytes of input are received in an 8-byte buffer `buf`. After `buf`, there's an 8-byte saved `RBP` value and an 8-byte return address. By sending `b'A' * 16` followed by the address of `win()`, it's possible to call the `win()` function.