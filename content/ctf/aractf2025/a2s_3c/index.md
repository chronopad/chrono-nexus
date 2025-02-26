---
title: "ARA CTF 6.0 2025 Finals: a2s 3c"
date: 2025-02-26
draft: false
summary: Differential Cryptanalysis to recover encryption key on reduced round AES.
tags:
  - cryptography
  - AES
  - cryptanalysis
category: Cryptography
---
##### Decompiling the Source
Challenge files: [here](https://github.com/chronopad/chrono-archive/tree/main/ctftime/KashiCTF_2025/misc/Broken)

In this challenge, we are provided with *chall.zip*, *out.txt*, and *pairs.txt*. The zip archive contains *chall.cpython-311.pyc*, *utils.cpython-311.pyc*, *aes.cpython-311.pyc*. 

The challenge source code is compiled Python, which can be decompiled with https://pylingual.io/. The decompiled code shows obfuscated variable name, so I asked ChatGPT to change the variable names into a more readable format.

##### Understanding the Challenge
###### Challenge Functions
One of the given files is the source code for AES implementation. This usually hints that the AES used is customized (a non-standard AES). 

The challenge starts with generating a random 16 bytes key for AES and calls the function `generate_encryption_pairs()`. This function creates five blocks with the length of 16 bytes, where the first 4 bytes of each blocks are unique random bytes and the remaining 12 bytes of the blocks are null bytes. It will then encrypt the blocks with `custom_encrypt()` function. The raw blocks and encrypted blocks are then used to create the encryption pairs.

```
# Example of a single encryption pair

176a3336000000000000000000000000
56d32528000000000000000000000000
a6830b1a039cf44917aba0318057cea5
50cfdab0b57af032d3c5bd76077a305d
```

The `custom_encrypt()` function starts by creating an instance of the `AES` class, passing `KEY` and `2` as parameters. The `2` here shouldn't exist in regular AES implementation, so that's something that we should take a look on. After creating the instance, it encrypts the block normally with AES, followed by `add_round_key()`, `mix_columns()`, and `add_round key()` again, then it returns the resulting block.

###### AES in a Nutshell
Here's how AES encryption works in a nutshell:
- The master key of AES is expanded into multiple round keys using AES key schedule.
- There are four main functions.
	- `AddRoundKey`, where the state is XOR-ed with the round key.
	- `SubBytes`, where each byte of the state is replaced with another byte based on a lookup table.
	- `ShiftRows`, where the rows are shifted based on their position, second row shifted by 1, third row by 2, and last row by 3.
	- `MixColumns`, where the four bytes of each column are combined and mixed together,
- The first phase is **pre-whitening**, which is done by performing `AddRoundKey`.
- After the first phase, there will be `n-1` rounds done for `n` is the number of AES rounds. For each round, these steps will be performed sequentially: `SubBytes` > `ShiftRows` > `MixColumns > AddRoundKey`. This is called as full round.
- After it is done, a final round takes place where the steps are the same except that now there is no `MixColumns`: `SubBytes` > `ShiftRows` > `AddRoundKey`. This is also called as half-round.

###### The Vulnerability
The first unique thing in the encryption here is the creation of the AES instance with `AES(KEY, 2)`. If we take a look at the decompiled code, we can see that `2` stands for the number of rounds. A normal 128-bit (16 bytes) AES will do 10 rounds, but in this one only 2 happens. Also since the custom encryption function adds `AddRoundKey` > `MixColumns` > `AddRoundKey` on top of the encryption, the final round which is usually a half round became a full round instead.

Based on the information, we can conclude that the AES encryption uses only 2 full rounds of encryption instead of the standard 10 rounds (9 full + 1 half). This means that the encrypted block of AES is not mixed properly yet, allowing us to perform Linear and Differential Cryptanalysis which allows us to retrieve the AES master key.

##### Attacking the Cipher
###### Differential Cryptanalysis
I browsed around for possible attacks on low round AES and I found [BlockBreakers](https://www.davidwong.fr/blockbreakers/) by David Wong which shows an attack called Square attack for breaking 4-6 rounds of AES. However, this is not the one I am looking for and I was unable to solve this challenge during the time limit (so this is an up-solve).

After the competition, found that the keyword "AES low round attack" leads to [this blog](https://merri.cx/adventure-of-aes/) by Merricx that shows the exact attack that I need. The blog explains about how to break 1 to 3-round AES, which includes Differential chosen-plaintext attack to break two full rounds of AES. 

The attack used is a chosen-plaintext attack because we need the plaintext differential where the first column is non-zero differential and the rest are zero differential, which is quite specific. Thankfully the plaintext-ciphertext pairs given in *pairs.txt* already fit this criteria, where the first four bytes (first column) are random bytes and the remaining bytes are null bytes (00). This means that this must be the correct attack.

###### Performing the Attack
Since I can't explain the attack better than the original blog by Merricx, which contains a really good explanation already, I'll go straight to attacking it. This part is really simple because apparently the blog provides the Python implementation of the attack found [here](https://github.com/Merricx/aes-attack) as *round2-full-impossible-diff.py*, which is an Impossible Differential chosen-plaintext attack that requires five plaintext-ciphertext pairs, exactly what we have right now. 

After a slight modification to the script to parse the plaintext-ciphertext pairs and also to decrypt with the obtained key, we should be able to get the flag.

```
import os, random
from Crypto.Util.strxor import strxor
from itertools import product
from aes import AES
from utils import *

#KEY = b"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C"
KEY = os.urandom(16)

# Encryption oracle
def encrypt(plaintext):
    aes = AES(KEY, 2)
    key_expand = aes._key_matrices

    state = aes.encrypt_block(plaintext)
    state = bytes2matrix(state)
    add_round_key(state, key_expand[-1])
    mix_columns(state)
    add_round_key(state, key_expand[-1])
    
    return matrix2bytes(state)

# Decryption check
def decrypt(ciphertext, key):
    aes = AES(key, 2)
    key_expand = aes._key_matrices
    state = bytes2matrix(ciphertext)
    add_round_key(state, key_expand[-1])
    inv_mix_columns(state)
    add_round_key(state, key_expand[-1])

    return aes.decrypt_block(matrix2bytes(state))


def generate_sbox_different_distribution_table():
    table = {}
    for i in range(256):
        for j in range(256):
            diff = i ^ j
            diff_sbox = sbox[i] ^ sbox[j]

            if diff in table:
                if diff_sbox not in table[diff]:
                    table[diff].append(diff_sbox)
            else:
                table[diff] = [diff_sbox]

    return table

# Inverse state from ciphertext to start of Round 2 
def inv_last_round(s, k):
    state = bytes2matrix(s)
    round_key = bytes2matrix(k)
    inv_mix_columns(state)
    add_round_key(state, round_key)
    inv_shift_rows(state)
    inv_sub_bytes(state)

    return matrix2bytes(state)

def mix_columns_key(round_key):
    state = bytes2matrix(round_key)
    mix_columns(state)

    return matrix2bytes(state)

# Generate list impossible state at the end of round 1 based from SBOX Different Distribution Table
def generate_impossible_state(differential):
    impossible = []
    for i in range(4):
        impossible.append([])
        for j in range(256):
            if j not in sbox_ddt[differential[i]]:
                impossible[i].append(j)

    impossible_state = []
    for i in range(4):
        
        for j in impossible[i]:
            state = bytes2matrix(b'\x00'*(i) + bytes([j]) + b'\x00'*(15-i))
            shift_rows(state)
            mix_columns(state)
            impossible_state.append(matrix2bytes(state))
            
    return impossible_state

def generate_256_list():
    result = []
    for i in range(256):
        result.append(i)

    return result

# Generate 5 chosen-plaintext such that each of their differential byte is unique
# So we can make 10 differential pairs from only 5 chosen-plaintext
def generate_sample_pair(n=5):

    while True:
        bs = []
        for i in range(n):
            bs.append(os.urandom(4))

        is_unique = True
        for i in range(4):
            exclude = []
            for j in range(n-1):
                for k in range(j+1, n):
                    check = bs[j][i] ^ bs[k][i]
                    if check not in exclude:
                        exclude.append(check)
                    else:
                        is_unique = False

        if is_unique:
            pairs = []
            ctx = []

            # Calls encryption oracle
            for i in range(n):
                p = bytes(bs[i]) + b'\x00'*12
                ctx.append(encrypt(p))

            for i in range(n-1):
                for j in range(i+1, n):
                    p1 = bytes(bs[i]) + b'\x00'*12
                    p2 = bytes(bs[j]) + b'\x00'*12
                    pairs.append([p1, p2, ctx[i], ctx[j]])

            return pairs

# ShiftRows 1 round
shifted_round1 = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]

# Generate Sbox Different Distribution Table
sbox_ddt = generate_sbox_different_distribution_table()

# Generate random sample of chosen-plaintext pairs that has unique XOR difference
print("[+] Retrieve 5 plaintext-ciphertext pairs from encryption oracle...")
# test_pair = generate_sample_pair()
test_pair = [[bytes.fromhex(block) for block in pair.split("\n")] for pair in open("../src/pairs.txt").read().split("\n\n")[:-1]]

impossible_key = [None] * 16

# Iterate over sample of chosen-plaintext
for plaintext1, plaintext2, ciphertext1, ciphertext2 in test_pair:

    print("[+] Checking impossible state from differential pair...")

    # Calculate XOR difference of plaintext and differential ciphertext 
    plain_diff = xor(plaintext1, plaintext2)
    enc_diff = xor(ciphertext1, ciphertext2)


    # Generate impossible start of round 2 state from pair sample
    impossible_state = generate_impossible_state(plain_diff)

    # Brute-force last round key one byte at time by comparing against impossible_state
    for i in range(16):
        if impossible_key[i] is None:
            impossible_key[i] = []

        shifted_index = shifted_round1[i]
        for j in range(256):
            if j in impossible_key[i]:
                continue

            # Inverse ciphertext to start of round 2 (ciphertext -> AddRoundKey -> InvShiftRows -> InvSubBytes)
            guess_key = b'\x00'*(i) + bytes([j]) + b'\x00'*(15-i)
            inv_a = inv_last_round(ciphertext1, guess_key)
            inv_b = inv_last_round(ciphertext2, guess_key)
            inv_diff = xor(inv_a, inv_b)
            
            # Check if inv_diff contained in one of impossible_state
            for k in impossible_state:
                if inv_diff[shifted_index] == k[shifted_index]:
                    impossible_key[i].append(j)

# Get possible_key by substracting all 256 possible value with impossible_key
list_256 = generate_256_list()
possible_key = []
for imp_key in impossible_key:
    possible_key.append(list(set(list_256) - set(imp_key)))

all_possible_key = product(*possible_key)

# Enumerate all remaining possible_key
ciphertext_check = ciphertext1
for possible_round_key in all_possible_key:
    
    mixed_key = mix_columns_key(possible_round_key)
    master_key = inv_key_expansion(list(mixed_key), 2)
    
    decrypt_check = decrypt(ciphertext_check, master_key)
    if decrypt_check == test_pair[-1][0]:
        print('[+] Possible Master Key:', master_key)

        encs = [bytes.fromhex(enc) for enc in open("../src/out.txt").read().split("\n")]
        pts = [decrypt(enc, master_key) for enc in encs]
        print("[+] Flag:", b''.join(pts))
        break
```

```
┌──(chronopad㉿VincentXPS)-[~/Documents/ctf2025/AraCTF-Finals_2025/a2s-upsolve/aes-attack]
└─$ python3 round2-full-impossible-diff.py
[+] Retrieve 5 plaintext-ciphertext pairs from encryption oracle...
[+] Checking impossible state from differential pair...
[+] Checking impossible state from differential pair...
[+] Checking impossible state from differential pair...
[+] Checking impossible state from differential pair...
[+] Checking impossible state from differential pair...
[+] Checking impossible state from differential pair...
[+] Checking impossible state from differential pair...
[+] Checking impossible state from differential pair...
[+] Checking impossible state from differential pair...
[+] Checking impossible state from differential pair...
[+] Possible Master Key: b'\xc3\x01\xa7\xd71\xe1O\xd1y\xf5Tm\x1c\xb95\xae'
[+] Flag: b'ARA6{2rounds_of_AES_arent_enough_hmmmm_maybe_3?}'
```

Flag: `ARA6{2rounds_of_AES_arent_enough_hmmmm_maybe_3?}`

##### Resources
- https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
- https://www.davidwong.fr/blockbreakers/aes_10_encryption.html
- https://merri.cx/adventure-of-aes/
- https://github.com/Merricx/aes-attack