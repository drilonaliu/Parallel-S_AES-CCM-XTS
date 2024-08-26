# Parallel-S_AES-Implementations
 
Simplified AES (S-AES) works the same way as the AES algorithm, with the difference being that S-AES uses 16 bit key for encryption instead of AES that normally uses 256. To achieve parallelization, S-AES uses 16 threads for parallel encryption/decryption of 16 bits. The text is converted to binary from CPU and then this array of bits is send to GPU for encryption. In addition to parallelization of S-AES, two modes that use SAES for encryption/decryption are also parallelized; CCM and XTS.

## CCM 

CCM - Counter with Cipher-Block Chaining Message Authentication is an authenticated encryption, which means that simultaneosly protects confidentiallity and authenticity (integrety) of communications. 

The algorithm for CCM encryption is given below.

<div>
  <p>
    <img src="images/CCM_1.png">
    <img src="images/CCM_2.png">
     <img src="images/CCM_3.png">
  </p>
</div>

## XTS
 
The XTS-AES is a block cipher mode of operation, approved by NIST in 2010. The XTS-AES algorithm uses the AES algorithm twice and uses two keys. The following parametres are associated with the algorithm.
 * Key - 256 or 512 bit XTS-AES key; this is parsed as a concatination of two fields of equal size Key1 and Key2, such that Key = Key1 || Key2. For SAES Key has a length of 32 bits, Key1 and Key2 being both 16 bits.
 * Pj - The jth block of the plaintext. All blocks except possibly the final block have a length of 128 bits (for SAES 16 bits). A plaintext data unit, typically a disk sector, conssits of the sequence P1,P2,,...Pm.
 * Cj - The jth block of cipher text. All blocks except possibly the final block have a length of 128 bits (for -AES 16 bits).
 * j - The sequential number of the 128-bit block inside the data unit.
 * i - The value of the 128-bit tweak. Each data unit (sector) is assigned a tweak value that is a nonnegative integer. The tweak values are assigned consecuitevely, starting from an arbritary nonnegative integer.
 * a - A primitive element of GF(2^128) that corresponds to the polynomial x ( 0000...10). (for S-AES we have GF(2^16).
 * a^j - a multiplied by itself j times, in GF(2^128) (for S-AES, GF*2^16).

The XTS-AES operation on Single block is given on the scheme below. 

<div>
  <p>
    <img src="images/XTS_1.png">
  </p>
</div>

The full XTS-AES mode is given with the scheme below. 

<div>
  <p>
    <img src="images/XTS_2.png">
  </p>
</div>

## Simplified AES

Simplified AES algorithm, has as input the block of length 16 bits, the key
16-bit length as well as the 16-bit block output. The algorithm has the actions SBOX, ShiftRows,
MixColums, AddRoundKey and their inverses InvSBOX, InvShiftRows, InvMixColums (
analogous to the AES algorithm).

### Encryption 

It has three rounds, where two firs rounds are identical and the third round does not have MixColoumns. Let $P$ be plain text and $K_0$ be the key.  

$$ 
A =
\begin{vmatrix}
A_0 & A_1 \\
A_2 & A_3  \\
\end{vmatrix}
$$

$$ 
K_0 =
\begin{vmatrix}
K_0 & K_1 \\
K_2 & K_3  \\
\end{vmatrix}
$$

, where $A_i$ and $K_j$ are 4 bits in a hexadecimal form so $A_i,k_j \in \set {0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}$

$$ 
P \oplus{K_0 =
\begin{vmatrix}
A_0 & A_1 \\
A_2 & A_3  \\
\end{vmatrix}}
\oplus{
\begin{vmatrix}
K_0 & K_1 \\
K_2 & K_3  \\
\end{vmatrix}} =
\begin{vmatrix}
B_0 & B_1 \\
B_2 & B_3  \\
\end{vmatrix} = 
B
$$

Then B enters in the below structure (Three rounds). First SBOX substitution is made, given with the

$$
SBOX = 
\begin{vmatrix}
6_{16} & B_{16} & 0_{16} & 4_{16} \\
7_{16} & E_{16} & 2_{16} & F_{16} \\
9_{16} & 8_{16} & A_{16} & C_{16} \\
3_{16} & 1_{16} & 5_{16} & D_{16} \\
\end{vmatrix}
$$

This SBOX is built within the Galois Field $GF(2^4)$ with the irreducible polynom $x^4+x+1$. The substitution is made such that the first two bits of $B_i$ tell the row and the last two bits indicate the coloumn of the SBOX. Then $B_i$ gets subsituted with the SBOX value where the coloumn and the row intersect. 

$$
SBOX(
\begin{vmatrix}
B_0 & B_2 \\
B_1 & B_3  \\
\end{vmatrix}) =
\begin{vmatrix}
C_0 & C_1 \\
C_2 & C_3 \\
\end{vmatrix}
$$
 
$$
ShiftRows(
\begin{vmatrix}
C_0 & C_2 \\
B_1 & C_3  \\
\end{vmatrix}) =
\begin{vmatrix}
C_0 & C_2 \\
C_3 & C_1 \\
\end{vmatrix}
$$

Then comes the MixColoumns operation, where the multiplication with Maximal Distance Separabile matrix) and the result from ShiftRows operation. The MDS matrix for MixColoumnns is 

$$
\begin{vmatrix} 
1_{16} & 1_{16} \\
1_{16} & 2_{16} \\
\end {vmatrix}
\begin{vmatrix} 
C_{0} & C_{2} \\
C_{3} & C_{1} \\
\end {vmatrix} = 
\begin{vmatrix} 
1_{16} *C_0+1_{16}*C_3  & 1_{16} *C_2+1_{16}*C_1 \\
1_{16} *C_0+2_{16}*C_3  & 1_{16} *C_2+2_{16}*C_1 \\ 
\end {vmatrix} =
\begin{vmatrix}
D_0 & D_2 \\
D_1 & D_3 \\
\end{vmatrix}
$$

where multiplication and addition is performed within the Galuois Field $GF(2^4)/x^4+x+1$


In AddRoundKey, the obtained matrix XOR-s with the KEY from the first round $K_1$ which is generated(similiarly with $K_2$ and $K_3$).

$$
\begin{vmatrix}
D_0 & D_2 \\
D_1 & D_3 \\
\end{vmatrix}
\oplus{K_1}=
\begin{vmatrix}
D_0 & D_2 \\
D_1 & D_3 \\
\end{vmatrix}
\oplus{\begin{vmatrix}
k_0 & k_2 \\
k_1 & k_3 \\
\end{vmatrix}} =
\begin{vmatrix}
E_0 & E_2 \\
E_1 & E_3 \\
\end{vmatrix}
$$

This matrix goes in again in the second round with the same repetition of operations and then again in round 3.

Below is given the encryption scheme for simplified AES.

![sAES scheme](https://user-images.githubusercontent.com/84543584/201967408-6d6579d6-f09d-4faf-bcfc-4a5e94baa189.png)

## Decryption

It has three rounds, where the first round does not have InvMixColoumns and two last rounds are identical(second and the third round).

Given the encrypted text $C$ and generated Key $K_3$ where $A_i$ and $k_j$ are each 4 bit in a hexadecimal form so $A_i, k_j \in{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}$.

$$ 
C = 
\begin{vmatrix}
A_0 & A_2 \\
A_1 & A_3 \\
\end{vmatrix} 
$$

$$ 
K_3 = 
\begin{vmatrix}
k_{12} & k_{14} \\
k_{13} & k_{15} \\
\end{vmatrix} 
$$

In the first round the first operation is AddRound Key, so it is calculated

$$
P \oplus{K_3} = 
\begin{vmatrix}
A_0 & A_2 \\
A_1 & A_3 \\
\end{vmatrix}
\oplus{
\begin{vmatrix}
k_{12} & k_{14} \\
k_{13} & k_{15} \\
\end{vmatrix}} =
\begin{vmatrix}
A_0 \oplus {k_{12}} & A_2 \oplus {k_{14}} \\
A_1 \oplus {k_{13}} & A_3 \oplus {k_{15}} \\
\end{vmatrix} = 
\begin{vmatrix}
B_0 & B_2 \\
B_1 & B_3 \\
\end{vmatrix}
$$

After AddRoundKey, comes InvShiftRows, where the second row is shifted right for four bits.

$$
InvShiftRows(
\begin{vmatrix}
B_0 & B_2 \\
B_1 & B_3 \\
\end{vmatrix}) =
\begin{vmatrix}
B_0 & B_2 \\
B_3 & B_1 \\
\end{vmatrix}
$$

Then the substitution is done with the InvSBOX given with the matrix\table:

$$
InvSBOX = 
\begin{vmatrix}
2_{16} & D_{16} & 6_{16} & C_{16} \\
3_{16} & E_{16} & 0_{16} & 4_{16} \\
9_{16} & 8_{16} & A_{16} & 1_{16} \\
B_{16} & F_{16} & 5_{16} & 7_{16} \\
\end{vmatrix}
$$

This InvSBOX is built within the Galois Field $GF(2^16)$ with the irreducible polynomial $x^4+x+1$. The substitution is done in such way that the first two bits of $B_i$ represent the row of the InvSBOX-it and the last two bits represent the coloumn of the InvSBOX. Then $B_i$ gets subsituted with the SBOX value where the row and the coloumn intersect. 

$$
InvSBOX(
\begin{vmatrix}
B_0 & B_2 \\
B_3 & B_1 \\
\end{vmatrix}) =
\begin{vmatrix}
C_0 & C_2 \\
C_1 & C_3 \\
\end{vmatrix}
$$

After InvSBOX the first round ends and then the two last rounds begin. 

In the second round, AddRoundKey is performed first, where the obtained value  XOR-s the second round key $K_2$ which is also generated just like ($K_1$ and $K_0$).

$$
\begin{vmatrix}
C_0 & C_2 \\ 
C_1 & C_3 \\
\end{vmatrix}
\oplus{K_2} =
\begin{vmatrix}
C_0 & C_2 \\ 
C_1 & C_3 \\
\end{vmatrix}
\oplus{
\begin{vmatrix}
k_8 & k_{10} \\ 
k_9 & k_{11} \\
\end{vmatrix}} =
\begin{vmatrix}
T_0 & T_2 \\
T_1 & T_3 \\
\end{vmatrix}
$$

Then comes the MixColoumns operation, where the multiplication with Maximal Distance Separabile matrix) and the result from InvShiftRows operation. The MDS matrix for InvMixColoumnns is 

$$
\begin{vmatrix} 
F_{16} & E_{16} \\
E_{16} & E_{16} \\
\end {vmatrix}
\begin{vmatrix} 
T_{0} & T_{2} \\
T_{3} & T_{1} \\
\end {vmatrix} = 
\begin{vmatrix} 
F_{16} *T_0+E_{16}*T_3  & F_{16} *T_2+E_{16}*T_1 \\
E_{16} *T_0+E_{16}*T_3  & E_{16} *T_2+E_{16}*T_1 \\ 
\end {vmatrix} =
\begin{vmatrix}
D_0 & D_2 \\
D_1 & D_3 \\
\end{vmatrix}
$$

where multiplication and addition is done within Galois Field $GF(2^16)/x^4+x+1$.

Then after InvMixColoumns comes InvShiftRows, where the second row is shifted right for four bits. 

$$
InvShiftRows(
\begin{vmatrix}
D_0 & D_2 \\
D_1 & D_3 \\
\end{vmatrix}) =  
\begin{vmatrix}
D_0 & D_2 \\
D_3 & D_1 \\
\end{vmatrix})
$$

Then the substitution happens with the InvSBOX(inverse of SBOX)

$$
InvShiftRows(
\begin{vmatrix}
D_0 & D_2 \\
D_3 & D_1 \\
\end{vmatrix}) =  
\begin{vmatrix}
P_0 & P_2 \\
P_1 & P_3 \\
\end{vmatrix})
$$

This matrix goes back again in the third round with the repetition of the operations and finally in the end it XOR-s with the key $K_0$. 

$$
R \oplus{K_0} = 
\begin{vmatrix}
R_0 & R_2 \\ 
R_1 & R_3 \\
\end{vmatrix}
\oplus{
\begin{vmatrix}
k_0 & k_2 \\ 
k_1 & k_3 \\
\end{vmatrix}}= 
\begin{vmatrix}
R_0 \oplus {k_{0}} & R_2 \oplus {k_{2}} \\
R_1 \oplus {k_{1}} & R_3 \oplus {k_{3}} \\
\end{vmatrix} =
\begin{vmatrix}
L_0 & L_2 \\
L_1 & L_3 \\
\end{vmatrix}
$$


Below is given the Simplified AES decryption scheme: 
![decryption SAES](https://user-images.githubusercontent.com/84543584/201981715-eab3a744-5803-4a85-ac3f-84cfbe7a0ca2.png)

## Key round generation 

Three keys are generated for both encryption and decryption for SAES. Below is given the scheme: 

![keyAES](https://user-images.githubusercontent.com/84543584/201982414-84b63d2e-3915-44a8-ae1d-1db0b336dc62.png)

## References 

William Stallings - Cryptograph and Network Security, Principles and Practice
