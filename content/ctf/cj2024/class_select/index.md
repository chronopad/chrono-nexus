---
title: "Cyber Jawara National 2024: Class Select"
date: 2025-01-12
draft: false
summary: Abusing the encryption of other AES modes to break AES OFB mode.
tags:
  - cryptography
  - AES
  - mode-abuse
category: Cryptography
---
##### Challenge Analysis
Challenge file: [here](https://github.com/chronopad/chrono-archive/tree/main/national/CyberJawara_2024/classselect)

The challenge only provides us with *chall.py* and a connection to server.

###### Main Function
The challenge starts by encrypting `PASSWORD` with AES and a random IV. It uses AES implementation from PyCryptodome, so let's take a look at the [docs](https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html) to see which AES mode is used. Based on the documentation, AES mode 5 is the OFB (Output Feedback) mode. It then prints out the encrypted password along with the IV.

After that, the challenge turns into an encryption and decryption oracle, giving us three chances to do three different types of actions, being:
- Encrypt, where we can encrypt any message using the parameters that we input.
- Decrypt, where we can decrypt any message using the parameters that we input.
- Guess, where we can guess the value of `PASSWORD`, also giving us the flag if we guessed correctly.

###### User Input Function
This function takes in the data to encrypt/decrypt in the form of hex encoding and also the AES parameters in form of JSON. There's a check in this function to ensure that the data length is under 41 bytes, which also means that we can only encrypt 32 bytes max or 2 blocks of AES since AES only accepts increment of 16 bytes.

###### Check Mode Function
This function is the main problem of this challenge. Every encryption and decryption done will check and store the AES mode to `used` list, so we can't use the same mode twice for the oracle. The challenge here is to decrypt the encrypted password, which spans four blocks, within two actions of encryption and decryption. We can only do two actions since the last one will be used to guess the password. 

##### Decrypting the Password
###### Attack Preparation
Let's start by taking a look at the OFB mode encryption. Here we can see that the plaintext is XOR-ed with encrypted IV to get the first ciphertext. The encrypted IV is further encrypted to be XOR-ed with the next ciphertext. 

![Image Description](/images/Pasted%20image%2020250304095505.png)

```
# Encryption model
PASSWORD_BLOCK1 ^ ENC(IV) = CIPHERTEXT_BLOCK1
PASSWORD_BLOCK2 ^ ENC(ENC(IV)) = CIPHERTEXT_BLOCK2
PASSWORD_BLOCK3 ^ ENC(ENC(ENC(IV))) = CIPHERTEXT_BLOCK3
PASSWORD_BLOCK4 ^ ENC(ENC(ENC(ENC(IV)))) = CIPHERTEXT_BLOCK4
```

Based on the above encryption model, we know that we can recover the password by getting the `ENC(IV)`, `ENC(ENC(IV))`, `ENC(ENC(ENC(IV)))`, `ENC(ENC(ENC(ENC(IV))))`, which is just the IV encrypted once - IV encrypted four times with AES. We can encrypt two blocks at once, so we have to find a mode that encrypts the ciphertext of the first block to get the ciphertext of the next block in order to get the IV encrypted twice in one action. If we can find two modes that can do that, we can recover the password in just two actions (four blocks).

###### First Action: CBC Mode
Take a look at the CBC (Cipher Block Chaining) mode encryption. Here, the resulting ciphertext from block cipher encryption is XOR-ed with the next plaintext, then encrypted again using block cipher encryption.

![Image Description](/images/Pasted%20image%2020250304122011.png)

If we set the IV with the IV from the encrypted password then set the plaintext as 32 bytes as null bytes, `XOR(plaintext, IV)` will result in the IV itself. The IV will then be encrypted to be `ENC(IV)` as the first block. The encrypted IV is then XOR-ed with more null bytes to still be `ENC(IV)`. It is then encrypted and we get `ENC(ENC(IV))` as the second block.

###### Second Action: CFB Mode
For the second action, we'll use the CFB (Cipher Feedback) mode, with the encryption as seen below.

![Image Description](/images/Pasted%20image%2020250304122426.png)

When the IV is set as `ENC(ENC(IV))` and the plaintext is 2 blocks of null bytes, the resulting ciphertext will be `XOR(ENC(ENC(ENC(IV))), NULL)` or `ENC(ENC(ENC(IV)))` as the first block. This will then be encrypted again and XOR-ed with null bytes to get `ENC(ENC(ENC(ENC(IV))))` as the second block.

###### Performing the Attack
Here's a quick refresher on the encryption model.

```
# Encryption model
PASSWORD_BLOCK1 ^ ENC(IV) = CIPHERTEXT_BLOCK1
PASSWORD_BLOCK2 ^ ENC(ENC(IV)) = CIPHERTEXT_BLOCK2
PASSWORD_BLOCK3 ^ ENC(ENC(ENC(IV))) = CIPHERTEXT_BLOCK3
PASSWORD_BLOCK4 ^ ENC(ENC(ENC(ENC(IV)))) = CIPHERTEXT_BLOCK4
```

Now that we have gathered all the required blocks of encrypted IV, all we need to do is to XOR them with the encrypted password to get the plaintext `PASSWORD`, then submit it to get the flag. Let's compile all of it into a Python script and run it.

```
from pwn import *

def repeatingXor(ct, key):
    print(len(ct), len(key))
    res = [ct[i] ^ key[i % len(key)] for i in range(len(ct))]
    return bytes(res)

io = remote("20.6.89.33", 8040)
# io = process(["python3", "chall.py"])

io.recvuntil(b"Encrypted password: ")
ct = io.recvline().strip().decode()
io.recvuntil(b"IV: ")
iv = io.recvline().strip().decode()

print("ct:", ct)
print("iv:", iv)

# CBC mode for the first two blocks
io.sendlineafter(b">>> ", b"1")
data = b"00" * 32
io.sendlineafter(b"Data: ", data)
params = '{"mode": 2, "iv": "' + iv + '"}'
io.sendlineafter(b"Params: ", params.encode())
io.recvuntil(b"Result: ")
first_part = io.recvline().strip().decode()

# CFB mode for the last two blocks
io.sendlineafter(b">>> ", b"1")
data = b"00" * 32
io.sendlineafter(b"Data: ", data)
params = '{"mode": 3, "iv": "' + first_part[32:] + '", "segment_size": 128}'
io.sendlineafter(b"Params: ", params.encode())
io.recvuntil(b"Result: ")
second_part = io.recvline().strip().decode()

fullkey = first_part + second_part
password = repeatingXor(bytes.fromhex(ct), bytes.fromhex(fullkey))
print("Password:", password)

io.sendlineafter(b">>> ", b"3")
io.sendlineafter(b"Guess: ", password)
io.interactive()
```

```
┌──(chronopad㉿VincentXPS)-[~/Documents/ctf2025/CyberJawara_2024/classselect/solve]
└─$ python3 solve.py
[+] Opening connection to 20.6.89.33 on port 8040: Done
ct: 1c2b658a97523abe1a0a2d8805d976618f46b0feb62796374472503a2940319e3529c967b37fd82ad946d3033be3c607be1dcb8374b72081f798232ed665e39d
iv: 833cd2ac03e9321e0cf0e8ccf3c798c8
64 64
Password: b'4f8b03e4ffe75f677c7b76d1c6c67a7419f952c4625c97ef55d9aa8c2040470b'
[*] Switching to interactive mode
Gratz: CJ{deploying_on_dday_is_not_a_good_idea_54aa921ee9486967}
[*] Got EOF while reading in interactive
$
```

Flag: `CJ{deploying_on_dday_is_not_a_good_idea_54aa921ee9486967}`

##### Resources
- https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
- https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html
- https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation