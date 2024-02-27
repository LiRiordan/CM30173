
### In week 2 students learnt about attacks on ciphers and implemented some of them
### in the case of a Vernam cipher. They also worked on Substitution Permutation
### Networks (SPNs) and S-boxs. They implemented these in code.

import string

def string_xor(a:str,b:str) -> str:
    '''Function which bit-wise XORs two strings together. If lengths not equal then only xors
    the shorter of the two with start of longer.'''
    g = lambda x: (int(x[0]) + int(x[1])) % 2
    comb = [[x,y] for x,y in zip(a,b)]
    xor = map(g,comb)
    output = ''.join(str(x) for x in xor)
    return output

### Ciphertext only attack:
### Ciphertext -> key, plaintext or allows attacker to encrypt more plaintext.

### Known plaintext attack:
### Plaintext and Ciphertext -> key or allows attacker to decrypt further ciphertext.

### Chosen plaintext attack:
### Plaintext and ciphertext for plaintext chosen by attacker
### -> key or allows attacker to decrypt further ciphertext.

### Adaptive chosen plaintext attack:
### Type of chose plaintext attack where attacker can update plaintexts based on previous attempts.

### Chosen ciphertext attack:
### Inverse of chosen plaintext attack.

###Vernam cipher:
### P = C = Z_2
### K = Z_2, keystream k_1k_2... with k_i in K
### plaintext x = x_1x_2...
### x_i -> (x_i + k_i) % 2
### decryption follows same process as we are mod 2

def Vernam_encrypt(plaintext,key):
    return string_xor(plaintext,key)

plaintext = '101000101'
key = '011101001'
ciphertext = Vernam_encrypt(plaintext,key)
test = Vernam_encrypt(ciphertext,key)
print(test == plaintext)  ### For Vernam decryption is same as encryption

### One-time pad is Vernam where the key is chosen randomly and never used again.

# Q2.1 Show Vernam is vulnerable to a known-plaintext attack
#Assume attacker knows ciphertext and plaintext
# Since y_i +/- x_i = k_i then they can find the key. (+/- since mod 2)
kpa_key = string_xor(ciphertext,plaintext)
print(kpa_key == key)

# Q2.2 Alice and Bob each decide on their own one-time pads,
# Alice fixes a plaintext x and key k. Bob fixes a key l.
# Alice encrypts c_1 as Vernam(x,k). Bob encrypts c_2 = Vernam(c_1,l).
# Alice encrypts c_3 as Vernam(c_2,k) = Vernam(x,l). Bob finally encrypts/decrypts
# plaintext = Vernam(c_3,l). Why can an attacker always recover the two keys and plaintext?

plaintext = '101000101' # = x
k = '011011100'
l = '110001111'
c_1 = Vernam_encrypt(plaintext,k)
c_2 = Vernam_encrypt(c_1,l)
c_3 = Vernam_encrypt(c_2,k)
c_4 = Vernam_encrypt(c_3,l)
print(c_4 == plaintext)

# note that the process looks like
# x_i
# -> x_i + k_i % 2      (c_1)
# -> x_i + k_i + l_i % 2        (c_2)
# -> x_i + 2k_i + l_i % 2 = x_i + l_i % 2       (c_3)
# -> x_i + 2l_i % 2 = x_i

# In particular if we only know c_1,c_2 and c_3 then
# we can compute k_i = (x_i + k_i + l_i) + (x_i + l_i) (c_2 xor c_3)
# and so can also find x_i = x_i + l_i + l_i (l xor c_3)
# likewise l_i = (x_i + k_i + l_i) + (x_i + k_i) (c_2 xor c_1)

### Example implementation:
attack_k = string_xor(c_2,c_3)
attack_l = string_xor(c_2,c_1)
attack_plaintext = string_xor(c_3,attack_l)
print(attack_k == k)
print(attack_l == l)
print(attack_plaintext == plaintext)

# Q2.3 If the attacker knows two ciphertexts encrypted with the same key under Vernam
# then by xor-ing the two ciphers we know the xor values of the two plaintexts.
# This reduces the possible plaintexts by 2. This will allow for a more efficient brute force attack.

# SPNs: Whilst many of the building blocks
# we saw in problem sheets so far don't provide
# secure encryptions, they may become more secure
# in combination. For an SPN we will combine substitution
# permutations and xor-ing.
import re

def decorator(f):
    def wrapper(text):
        args = list(text)
        output = map(f,args)
        x = ''.join(f'{x}' for x in output)
        return x
    return wrapper
sub_list = [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15]
perm_list = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
hex_list = ['{0:04b}'.format(int(t,16)) for t in string.hexdigits[:16].upper()]
@decorator
def pi_sub(x):
    sub_dict = {hex_list[i]:hex_list[sub_list[i]] for i in range(16)}
    return sub_dict[x]
def pi_perm(x):
    t = list(x)
    out = [t[i] for i in perm_list]
    return ''.join(out)
def SPN(plaintext,*keys,sub = pi_sub ,perm = pi_perm,l=4,m=4):
    '''Implementation of substitution-permutation
    network with default substitutions and permutations.
    Decryption assumes permutation was self inverse.'''
    state = plaintext
    for key in keys[:-2]:
        state = string_xor(state,key)
        sub_list = re.findall('.'*l,state)
        list_2= sub(sub_list)
        state = ''.join(list_2)
        state = perm(state)
    state = string_xor(state,keys[-2])
    sub_list = re.findall('.'*l,state)
    list_2 = sub(sub_list)
    state = ''.join(list_2)
    return string_xor(state,keys[-1])

plaintext = '0100111010100001'
k_1 = '1110011101100111'
k_2 = '0111011001111001'
k_3 = '0110011110010000'
k_4 = '0111100100000011'
k_5 = '1001000000111101'
cipher = SPN(plaintext,k_1,k_2,k_3,k_4,k_5)
print(cipher)

### To decrypt the SPN:
kd_1 = k_5
kd_2 = pi_perm(k_4)
kd_3 = pi_perm(k_3)
kd_4 = pi_perm(k_2)
kd_5 = k_1
@decorator
def decrpt_pi_sub(x):
    sub_dict = {hex_list[sub_list[i]]:hex_list[i] for i in range(16)}
    return sub_dict[x]

decrypt = SPN(cipher,kd_1,kd_2,kd_3,kd_4,kd_5,sub = decrpt_pi_sub)
print(decrypt == plaintext)
### Note we don't need to invert the permutation as the permutation
### is chosen to be self inverse.

### SPNs are closely related to the encryption method AES.
### A format of this called AES-GCM is one of the main encryptions
### used nowadays for internet traffic over https to servers.
