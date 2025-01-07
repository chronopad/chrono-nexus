---
title: "Crypto: knutsacque"
date: 2025-01-06
draft: false
summary: Iris CTF 2025. Knapsack problem with quaternions. LLL to recover message blocks.
tags: ["knapsack", "LLL", "matrix"]
category: Cryptography
---
##### Challenge
This challenge is upsolved from [the author's writeup](https://github.com/Seraphin-/ctf/blob/master/2025/irisctf/knutsacque.md). We are provided *chal.sage* and *output.txt*.

```
# chal.sage
import secrets

F.<i,j,k> = QuaternionAlgebra(-1, -1)
A = []
B = [1, i, j, k]

msg_bin = b"irisctf{redacted_redacted_redacted_}"
assert len(msg_bin) % 4 == 0
msg = [F(sum(Integer(msg_bin[idx+bi])*b for bi, b in enumerate(B))) for idx in range(0, len(msg_bin), len(B))]
targ = 2^64

for _ in range(len(msg)):
    a = F(sum(secrets.randbelow(targ)*b for b in B))
    A.append(a)

sm = F(0)
for idx in range(len(msg)):
    sm += msg[idx] * A[idx]

print("A =", A)
print("s =", sm)
```

```
# output.txt
A = [17182433425281628234 + 14279655808574179137*i + 8531159707880760053*j + 10324521189909330699*k, 10979190813462137563 + 11958433776450130274*i + 10360430094019091456*j + 11669398524919455091*k, 3230073756301653559 + 4778309388978960703*i + 7991444794442975980*j + 11596790291939515343*k, 11946083696500480600 + 18097491527846518653*i + 5640046632870036155*j + 2308502738741771335*k, 12639949829592355838 + 12578487825594881151*i + 5989294895593982847*j + 9055819202108394307*k, 15962426286361116943 + 6558955524158439283*i + 2284893063407554440*j + 14331331998172190719*k, 14588723113888416852 + 432503514368407804*i + 11024468666631962695*j + 10056344423714511721*k, 2058233428417594677 + 7708470259314925062*i + 7418836888786246673*j + 14461629396829662899*k, 4259431518253064343 + 9872607911298470259*i + 16758451559955816076*j + 16552476455431860146*k]
s = -17021892191322790357078 + 19986226329660045481112*i + 15643261273292061217693*j + 21139791497063095405696*k
```

The encryption starts by diving the message into blocks of four characters each, then use their ASCII values as coefficients to form a quaternion, which is a four dimensional vector. 

```
sage: msg = [F(sum(Integer(msg_bin[idx+bi])*b for bi, b in enumerate(B))) for idx in range(0, len(msg_bin), len(B))]
sage: msg
[105 + 114*i + 105*j + 115*k,
 99 + 116*i + 102*j + 123*k,
 114 + 101*i + 100*j + 97*k,
 99 + 116*i + 101*j + 100*k,
 95 + 114*i + 101*j + 100*k,
 97 + 99*i + 116*j + 101*k,
 100 + 95*i + 114*j + 101*k,
 100 + 97*i + 99*j + 116*k,
 101 + 100*i + 95*j + 125*k]
```

It will then generate a list of quaternions with the same size as the `msg` quaternions above. The coefficients for the quaternions are randomly generated 64 bit integers.

```
sage: for _ in range(len(msg)):
....:     a = F(sum(secrets.randbelow(targ)*b for b in B))
....:     A.append(a)
....:
sage: A
[13837388767782043972 + 7809201807996912089*i + 12986947397704081026*j + 609619010023959748*k,
 8771729123148867804 + 18103239779347531290*i + 6575900090027619404*j + 18328038587554093584*k,
 977244651506020571 + 12569942643005573095*i + 6978627459516744464*j + 6479286072282315114*k,
 12411012500437879663 + 2135025104182005264*i + 5425268026679454877*j + 702427975534281031*k,
 17100667416476938058 + 1808064680619569426*i + 7772845331222421881*j + 4476043718848060056*k,
 3814478570682782772 + 14090353431496533110*i + 2084415528130555435*j + 6783308246110605206*k,
 3715153897463101027 + 6448272151618476822*i + 15602473372192830651*j + 12939978103417235880*k,
 14634677867118958438 + 13682483499628209437*i + 2144135849019529928*j + 12058704514056147705*k,
 14930035260794662679 + 6646560134513752972*i + 6487028501149968035*j + 10209325974838223425*k]
```

It will then combine `A` and `msg` by multiplying the elements together. Each element of `A` and `msg` are quaternions, so the quaternion multiplication rule applies as shown below.

```
q1 = a1 + b1*i + c1*j + d1*k
q2 = a2 + b2*i + c2*j + d2*k

x = a1*​a2​ − b1*​b2 ​− c1*​c2​ − d1*​d2
y = a1*​b2 ​+ b1*​a2 ​+ c1*​d2 ​− d1*​c2
z = a1*​c2 ​− b1*​d2 ​+ c1*​a2 ​+ d1*​b2
w = a1*​d2 ​+ b1*​c2 ​− c1*​b2 ​+ d1*​a2

q1*q2 = x + y*i + z*j + w*k​​​
```

After all of the quaternions of `A` and `msg` are multiplied together, they are all summed into a single quaternion `sm` which is the result. Now we have to recover the value of `msg` given `A` and `sm`. 

##### Solution
If we pay a close attention, then we will notice that this is a Knapsack problem, as we are given a list of quaternions (general knapsack) `A` and the sum `sm`.  The Knapsack problem can be solved using LLL, so let's construct the matrix first. Here's how we can build the matrix `M` to use for the LLL based on [this paper](https://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic16/Knapsack.pdf).

![Image Description](/images/Pasted%20image%2020250106182359.png)

Some elements in matrix `M` here is still in form of quaternions, so we will have to convert them to into another matrix with elements in the complex field, followed by another conversion to another matrix with elements over the integers. Only then we can use LLL to the resulting matrix.

![Image Description](/images/Pasted%20image%2020250106200849.png)

![Image Description](/images/Pasted%20image%2020250106201002.png)

```
# Representation of a quaternion a + bi + cj + dk as matrix over Z
[ a -b  c -d]
[ b  a  d  c]
[-c -d  a  b]
[ d -c -b  a]
```

The output matrix of the LLL algorithm has to be sliced per blocks (per 4 elements) because it is formed from the quaternion `1, i, j, k`. We will then filter for valid results where the coefficients are valid ASCII values between 0 and 128, then check each valid results if they are the flag. Here's the full solve script.

```
F.<i,j,k> = QuaternionAlgebra(-1, -1)

load("output.sage") # output.txt
A = [F(a) for a in A]
sm = F(s)
n = len(A)

N = F(1024) # scaling

# Create matrix M
M = Matrix(F, n+1, n+1)
for i in range(n):
    M[i, i] = 1
    M[i, n] = N * A[i]
M[n, n] = N * sm

# Convert quaternion matrix to complex numbers (Z[i]) matrix
def quaterToComplexMatrix(M):
    rows = []
    for row in M:
        nr = [e[0]+e[1]*I for e in row] + [e[2]+e[3]*I for e in row]
        rows.append(nr)
    for row in M:
        nr = [-e[2]+e[3]*I for e in row] + [e[0]-e[1]*I for e in row]
        rows.append(nr)
    return matrix(ZZ[I], rows)

# Convert complex numbers matrix to matrix over the integers
def complexToRealMatrix(M):
    rows = []
    for row in M:
        nr = [e.real() for e in row] + [-e.imag() for e in row]
        rows.append(nr)
    for row in M:
        nr = [e.imag() for e in row] + [e.real() for e in row]
        rows.append(nr)
    return matrix(ZZ, rows)

Mc = quaterToComplexMatrix(M)
Mr = complexToRealMatrix(Mc)
M_reduced = Mr.LLL()

# Extract possible results (blocks) for the resulting matrix
possible_res = set()
for row in M_reduced:
	nl = len(row) // 4
	for ni in range(4):
		if all(int(x) > 0 and int(x) < 128 for x in row[ni*nl:ni*nl+nl-1]):
			possible_res.add(bytes([int(x) for x in row[ni*nl:ni*nl+nl-1]]))
		if all(int(-x) > 0 and int(-x) < 128 for x in row[ni*nl:ni*nl+nl-1]):
			possible_res.add(bytes([int(-x) for x in row[ni*nl:ni*nl+nl-1]]))
print(possible_res)

import itertools

# Test result for all ordering of the possible_res blocks
for per in itertools.permutations(possible_res, int(4)):
	curr = b"".join(bytes([per[nj][ni] for nj in range(4)]) for ni in range(len(per[0])))
	if b"irisctf{" in curr:
		print(curr)
		break
```

Flag: `irisctf{wow_i_cant_believe_its_lll!}`

Link, resources:
- https://en.wikipedia.org/wiki/Quaternion
- https://en.wikipedia.org/wiki/Complex_number
- https://github.com/Seraphin-/ctf/blob/master/2025/irisctf/knutsacque.md
- https://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic16/Knapsack.pdf
