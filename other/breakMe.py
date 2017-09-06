#!/usr/bin/pypy -u

import sys, string
from random import randint, choice
from hashlib import sha1

BLOCK_SIZE = 2

ROUNDS = 2**18 # ultimate security!

FBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]
FINVBOX = [0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5]

PBOX = [5, 2, 1, 13, 6, 8, 9, 15, 3, 14, 11, 4, 10, 12, 7, 0]
PINVBOX = [15, 2, 1, 8, 11, 0, 4, 14, 5, 6, 12, 10, 13, 3, 9, 7]

def permute(block, pbox):
    output = 0
    for i in xrange(8*BLOCK_SIZE):
        bit = (block >> pbox[i]) & 1
        output |= (bit << i)
    return output

def f(block, fbox):
    # split into 4-bit chunks
    splitblock = [(block >> (4*(2*BLOCK_SIZE - i - 1))) & 0xf for i in range(2*BLOCK_SIZE)]

    # substitute each chunk
    substituted = [fbox[s] for s in splitblock]

    # combine chunks
    return reduce(lambda x,y : x | y, [s << (4*(2*BLOCK_SIZE - i - 1)) for i,s in enumerate(substituted)])

def encrypt_block(block, keys):
    output = block
    for i in range(ROUNDS):
        output = permute(f(output ^ keys[i % len(keys)], FBOX), PBOX)
    return output

def decrypt_block(block, keys):
    output = block
    for i in range(ROUNDS):
        output = f(permute(output, PINVBOX), FINVBOX) ^ keys[len(keys) - 1 - (i % len(keys))] # use keys in reverse order
    return output

def encrypt(data, keys, IV):
    assert len(data) % BLOCK_SIZE == 0, "Input length must be a multiple of the block size"

    # split into blocks of BLOCK_SIZE
    split = [data[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE] for i in range(len(data) / BLOCK_SIZE)]
    blocks = [int(b.encode('hex'),16) for b in split]

    # CBC mode
    output_blocks = []
    chain = IV
    for block in blocks:
        encrypted = encrypt_block(block ^ chain, keys)
        output_blocks.append(encrypted)
        chain = encrypted


    # join the blocks back together
    return "".join([hex(long(b))[2:-1].rjust(2*BLOCK_SIZE, "0") for b in output_blocks]).decode('hex')

def decrypt(data, keys, IV):
    assert len(data) % BLOCK_SIZE == 0, "Input length must be a multiple of the block size"

    # split into blocks of BLOCK_SIZE
    split = [data[BLOCK_SIZE*i : BLOCK_SIZE*i+BLOCK_SIZE] for i in range(len(data) / BLOCK_SIZE)]
    blocks = [int(b.encode('hex'),16) for b in split]

    # CBC mode
    output_blocks = []
    chain = IV
    for block in blocks:
        decrypted = decrypt_block(block, keys) ^ chain
        output_blocks.append(decrypted)
        chain = block


    # join the blocks back together
    return "".join([hex(long(b))[2:-1].rjust(2*BLOCK_SIZE, "0") for b in output_blocks]).decode('hex')

def gen_keys():
    return (randint(0, 2**(8*BLOCK_SIZE)-1), randint(0, 2**(8*BLOCK_SIZE)-1))

def gen_IV():
    return randint(0, 2**(8*BLOCK_SIZE)-1)

def pad(s):
    if len(s) % BLOCK_SIZE == 0:
        return s
    return s.ljust(BLOCK_SIZE*((len(s) / BLOCK_SIZE) + 1), "\x00")

def main():
    welcome = \
"""
______  ___   _____ _____    _____ _   _ _____ ________   _______ _____ _____ _____ _   _    _____  _____ 
| ___ \/ _ \ |  ___/  ___|  |  ___| \ | /  __ \| ___ \ \ / / ___ \_   _|_   _|  _  | \ | |  / __  \|  _  |
| |_/ / /_\ \| |__ \ `--.   | |__ |  \| | /  \/| |_/ /\ V /| |_/ / | |   | | | | | |  \| |  `' / /'| |/' |
| ___ \  _  ||  __| `--. \  |  __|| . ` | |    |    /  \ / |  __/  | |   | | | | | | . ` |    / /  |  /| |
| |_/ / | | || |___/\__/ /  | |___| |\  | \__/\| |\ \  | | | |     | |  _| |_\ \_/ / |\  |  ./ /___\ |_/ /
\____/\_| |_/\____/\____/   \____/\_| \_/\____/\_| \_| \_/ \_|     \_/  \___/ \___/\_| \_/  \_____(_)___/ 

"""
    print welcome

    keys = gen_keys()
    IV = gen_IV()

    print "Before we encrypt your message, you'll have to do a proof of work."
    prefix = "".join([choice(string.digits + string.letters) for i in range(10)])
    print "Give me a string starting with {}, of length {}, such that its sha1 sum ends in ffffff".format(prefix, len(prefix)+5)
    response = raw_input()
    if sha1(response.strip()).digest()[-3:] != "\xff"*3 or not response.startswith(prefix):
        print "Doesn't work, sorry."
        exit()

    print "Here's the IV: %x" % IV
    flag = open("flag.txt").read()
    print "We're encrypting your flag. Just a minute, please..."
    enc = encrypt(pad(flag), keys, IV).encode('hex')

    print "Flag:", enc

    max_size = 2*400*BLOCK_SIZE
    pt = raw_input("Enter your message hex-encoded, we'll encrypt it (max length {}): ".format(max_size))

    if len(pt) > max_size:
        pt = pt[:max_size]

    print encrypt(pad(pt.decode('hex')), keys, IV).encode('hex')

if __name__ == "__main__":
    main()
