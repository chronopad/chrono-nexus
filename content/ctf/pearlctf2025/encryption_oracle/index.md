---
title: "Pearl CTF 2025: Encryption Oracle"
date: 2025-03-09
draft: false
summary: "Public modulus and public exponent recovery, factoring the public modulus from leak: d mod (p-1)."
tags:
  - cryptography
  - RSA
  - leaks
category: Cryptography
---
{{< katex >}}
![Image Description](/images/Pasted%20image%2020250308131727.png)

##### Challenge Analysis
Challenge files: [here](https://github.com/chronopad/chrono-archive/tree/main/ctftime/PearlCTF_2025/encryption-oracle)  
This challenge provides us with *server.py* and the server connection.

###### Parameter Generation
The challenge starts by generating the parameters for the RSA encryption. The primes used are 1024 bits each, and the public exponent used is a 20 bits prime number, which is different from the standard \\(e = 65537\\). After the calculation of the private key, an additional information leak: \\(leak = d \bmod (p-1)\\) is also calculated.

###### Encryption Oracle
From this oracle, we can encrypt a message and get the ciphertext for a total of three times. Along with it, we can also get the encrypted flag `ciphertext` and the `leak` for free. However, we are not given the value of the public exponent and public modulus. There's also a requirement that the message must have at least 600 bits.

##### Parameter Recovery to Factorization
###### Recovering Public Modulus
We can recover the public modulus in just three attempts of encrypting messages. This is done by encrypting \\(m\\), \\(m^3\\), and \\(m^9\\) and getting their respective ciphertext. We can arrange the resulting ciphertexts into the equation below, where if we subtract the previous ciphertext raised to the power of three from the current ciphertext, we can get a multiple of the public modulus.

$$\begin{align*} c_i &= c_{i-1}^3 \bmod n \\ c_i - c_{i-1}^3 &= 0 \bmod n \end{align*}$$

This means we can get three different multiples of the public modulus \\(n\\) from three ciphertexts.

$$c_1 - c_0^3 = 0 \bmod n$$
$$c_2 - c_1^3 = 0 \bmod n$$
$$c_2 - c_0^9 = 0 \bmod n$$

Since we now have three different multiples of the public modulus, we can try to find the GCD of these three values to recover the public modulus. Below is a script that I used to automate the process.

```
from pwn import *
from math import gcd, prod
from tqdm import tqdm
import itertools
from Crypto.Util.number import *

def encrypt_msg(msg):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Enter hex message: ", hex(msg).encode())
    io.recvuntil(b"Encrypted (hex): ")
    return int(io.recvline().strip().decode(), 16)

io = remote("encryption-oracle.ctf.pearlctf.in", 30012)
# io = process(["python3", "chall/server.py"])

io.sendlineafter(b"> ", b"2")
io.recvuntil(b"Encrypted flag: ")
enc_flag = int(io.recvline().strip().decode(), 16)

io.sendlineafter(b"> ", b"3")
io.recvuntil(b"Leak (d mod (p-1)): ")
leak = int(io.recvline().strip().decode())

# m = 2**600 -> exponent = [1, 3, 9]
ms = [4149515568880992958512407863691161151012446232242436899995657329690652811412908146399707048947103794288197886611300789182395151075411775307886874834113963687061181803401509523685376,
      71448348576730208360402604523024658663907311448489024669693316988935593287322878666163481950176220037593478347105937422686501991894419788796088422137966026262523598150372719976137911322484446114613284904383977643176193557817897027023063420124852033989626806764509137929914787205373413116077254242653423277386226627159120168223623660139965116969572411841665962582988716865792650075294655252525257343163566042824495509307872827973214736884381496689456792434150079470111661811761376161068055664012337698456291039551943299284254570579952324837376,
      364734282154381048030646304309052106190791433531778775620998444935497949132100044489744246359856303966133189679568623677222355506787481639161602670945959702639522306459508705793630639722772286011395018294163131881256947283664633792451493826789445489744273886978437173311110997887612371643826947092016319266485789676674936642121144880052421548066804185680667244670701569777857162209535462711477927357348443388696117733821433320353098203873600955463636635802048138805282119271167822792520615258583651034228726565153341463139040948455257378740497476474392659211690378633129056863796807917281090342662150318639879809492961736651011236862423316406020430716685336886249815412738731346368551152930689440219813532346902149372142499890166361458180605213246186088708967138367892539555110074649625909691120312155904835109788759135188483596106811524071197429343914697401608164985190578018095109540394302708528602015917954303927983425233850438042947322468454823914479563087114188948029781636028087157478983971323476692679109311135830495473549230477553114177506052940289630215962639686312585028309076084135103498179087226538263078506318131206512836741897818986436154714725386865432369356802242082067242694353549793213577685393357314607578653751157817107484871743141432332877523513766366051642948529346668649497821536980752940776170990525951791115277210665099910458857024989313038628789339850253787038526427444863742610847826950745248707138567386602728475043676636188300621934928290127020446172239944303781717526768728493839225001821713004725768862841697799796482368748357796570748145289691794065336929986960850713189465658109926251352293376,
      ]
cs = [encrypt_msg(m) for m in ms]

print("ms =", ms)
print("cs =", cs)
print("enc_flag =", enc_flag)
print("leak =", leak)

n1 = cs[0] ** 3 - cs[1]
n2 = cs[1] ** 3 - cs[2]
n3 = cs[0] ** 9 - cs[2]

n = gcd(gcd(n1, n2), n3)
print("n =", n)
print("Bit length of the public modulus:", n.bit_length())
```

###### Recovering Public Exponent
My approach for recovering the public exponent is to brute-force all of the 20 bits long integers, which means integers between \\(2^{19}\\) and \\(2^{20}\\). There are only around \\(500000\\) possibilities, so brute-force is still feasible.

```
for i in tqdm(range(524288, 1048576)):
    if pow(ms[0], i, n) == cs[0]:
        print("e =", i)
        break 
```

###### Factoring the Modulus from Leak
Information and steps for factorization:
- The private exponent \\(d\\) satisfies \\(e . d = 1 \bmod φ(n)\\), where \\(φ(n) = (p-1)(q-1)\\). 
- We are given a leak where \\(leak = d \bmod (p-1)\\), which can also be written as \\(d = leak + k(p-1)\\).
- Since \\(d\\) is the inverse of \\(e \bmod φ(n)\\), it also holds for modulo \\((p-1)\\), written as \\(e . d = 1 \bmod (p-1)\\). If we substitute in \\(d = leak + k(p-1)\\), we will get the equation \\(e . leak = 1 \bmod (p-1)\\).
- The equation means that \\(p-1\\) is a factor or divisor of \\(e.leak - 1\\). Since we know the value of both \\(e\\) and \\(leak\\), we can try to find the factors of \\(e.leak - 1\\). 
- For each factor \\(t\\), we can check if \\(t + 1\\) divides \\(n\\). If it does, then we have found \\(p\\).

I use FactorDB to get the main factors of \\(e.leak - 1\\), then created a Python script to loop for every combinations (and subsets) of the factors to find the value of \\(p\\). The `facs_primary` is the largest number that can't be factored by FactorDB, but the number must be a part of \\(p\\). It is multiplied by \\(2\\) because \\(p\\) is a prime number, so \\(p - 1\\) must be an even number.

```
facs_primary = 2327966142186625703203675744219978823417989720626326216096238659578127827462271043086388598230800516171536997637969849607606680317223637055410628186200775167477277149038603080734943890372183478247661201822938890646376996789639562474353476533495081966804762659145088917257202156435904567879997051853*2
facs_secondary = [397, 263, 103, 13, 11, 5, 5, 5, 5, 3, 3, 3, 3, 3, 2, 2, 2]

def all_subsets(arr):
    return [list(combo) for r in range(len(arr) + 1) for combo in itertools.combinations(arr, r)]

subsets = all_subsets(facs_secondary)
for i in tqdm(range(len(subsets))):
    p = facs_primary * prod(subsets[i]) + 1
    if isPrime(p) and p.bit_length() == 1024:
        print("p =", p)
        break
```

###### Decrypting the Flag
If we successfully find \\(p\\), we can just calculate the private exponent \\(d\\) and decrypt the flag.

```
p = 106376261549418619377221254893208558037461518114688135733313579293909678497579690266214726380897544584424831957162185809779362762661313475710580053277612318227488293302304280264983013299204049846600792519321074117058304853797788480694021277222083093292815787400061993643288230820198490895479553084614464555001
q = n // p 
d = pow(e, -1, (p-1)*(q-1))
print(long_to_bytes(pow(enc_flag, d, n)))
```

Flag: `pearl{RSA_1s_n0t_that_easy}`
