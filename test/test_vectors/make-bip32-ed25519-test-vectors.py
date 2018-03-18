#!/usr/bin/python3 

import hmac
import hashlib
import binascii
import json
import sys
import random
import ed25519

def h512(m):
    return hashlib.sha512(m).digest()

def h256(m):
    return hashlib.sha256(m).digest()

def Fk(message, secret):
    return hmac.new(secret, message, hashlib.sha512).digest()

def set_bit(character, pattern):
    return character | pattern

def clear_bit(character, pattern):
    return character & ~pattern

def root_key(master_secret):
    k = bytearray(h512(master_secret))
    kL, kR = k[:32], k[32:]

    if kL[31] & 0b00100000:
        return None

    # clear lowest three bits of the first byte
    kL[0]  = clear_bit( kL[0], 0b00000111)
    # clear highest bit of the last byte
    kL[31] = clear_bit(kL[31], 0b10000000)
    # set second highest bit of the last byte
    kL[31] =   set_bit(kL[31], 0b01000000)

    # root public key
    A = ed25519.encodepoint(ed25519.scalarmult(ed25519.B, int.from_bytes(kL, 'little'))).encode('iso-8859-1')
    # root chain code
    c = h256(b'\x01' + master_secret)
    return ((kL, kR), A, c)

def private_child_key(node, i):
    if not node:
        return None
    # unpack argument
    ((kLP, kRP), AP, cP) = node
    assert 0 <= i < 2**32

    i_bytes = i.to_bytes(4, 'little')
    if i < 2**31:
        # regular child
        Z = Fk(b'\x02' + AP + i_bytes, cP)
        c = Fk(b'\x03' + AP + i_bytes, cP)[32:]
    else:
        # harderned child
        Z = Fk(b'\x00' + (kLP + kRP) + i_bytes, cP)
        c = Fk(b'\x01' + (kLP + kRP) + i_bytes, cP)[32:]

    ZL, ZR = Z[:28], Z[32:]

    kLn = int.from_bytes(ZL, 'little') * 8 + int.from_bytes(kLP, 'little')
    if kLn % ed25519.l == 0:
        return None
    kRn = (
        int.from_bytes(ZR, 'little') + int.from_bytes(kRP, 'little')
    ) % 2**256
    kL = kLn.to_bytes(32, 'little')
    kR = kRn.to_bytes(32, 'little')

    A = ed25519.encodepoint(ed25519.scalarmult(ed25519.B, int.from_bytes(kL, 'little'))).encode('iso-8859-1')
    return ((kL, kR), A, c)

def derive_chain(master_secret, chain):
    root = root_key(master_secret)
    node = root

    for i in chain.split('/'):
        if not i:
            continue
        if i.endswith("'"):
            i = int(i[:-1]) + 2**31
        else:
            i = int(i)
        node = private_child_key(node, i)
    return node


if __name__ == '__main__':

    random.seed(0)
    for k in range(0, 1000):
        path = ''
        secret = binascii.hexlify(random.getrandbits(256).to_bytes(32, 'little')).decode('iso-8859-1')
        n = random.randint(0,10)
        for j in range(0, n):
            c = random.randint(0,3)
            if c == 0:
                i = random.randint(0, 100)
            elif c == 1:
                i = random.randint(2**31 - 50, 2**31 + 50)
            elif c == 2:
                i = random.randint(2**32 - 100, 2**32 - 1)
            else:
                i = random.randint(0, 2**32 -1 )

            if i >= 2**31:
                path += "%d'/" % (i-2**31)
            else:
                path += "%d/" % i

        if path:
            path = path[:-1]
        node =  derive_chain(binascii.unhexlify(secret), path)
        if node:
            ((kLP, kRP), AP, cP) = node
            node =  {
                'kLP':    binascii.hexlify(kLP).decode('iso-8859-1'),
                'kRP':    binascii.hexlify(kRP).decode('iso-8859-1'),
                'AP':     binascii.hexlify(AP).decode('iso-8859-1'),
                'cP':     binascii.hexlify(cP).decode('iso-8859-1')
            }
        print(json.dumps({
            'secret': secret,
            'path':  path,
            'node': node
        }))
