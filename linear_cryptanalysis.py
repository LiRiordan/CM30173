import string
from Week_2 import SPN, string_xor
from Week_3 import sub, inv_sub
import pandas as pd
import numpy as np
from IPython.display import display
import random
import re
sub_list = [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15]
perm_list = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
hex_list = ['{0:04b}'.format(int(t,16)) for t in string.hexdigits[:16].upper()]
labels = [t for t in string.hexdigits[:16].upper()]

### In differential cryptanalysis we performed a chosen plaintext attack by finding
### high likelyhood differences between inputs and states before the last round.

### In linear cryptanalysis we don't need a chosen plaintext attack, only a known plaintext
### attack. We will look at linear equations between plaintexts and the state before the last round
### which hold a sufficient proportion of the time.


### We first create a table containing the biases towards certain linear relations
### between bits under the S-box substitution.

Analysis_array = np.zeros([16,16])
for i in hex_list:
    for j in hex_list:
        for k in hex_list:
            out = sub(k)
            total = 0
            for r in range(4):
                total += int(i[r])*int(k[r])
            for s in range(4):
                total += int(j[s])*int(out[s])
            if total % 2 == 0:
                Analysis_array[hex_list.index(i),hex_list.index(j)] += 1
for i in range(16):
    for j in range(16):
        Analysis_array[i,j] -= 8 ### want to centre the array on bias rather than count.

pd.set_option('display.max_columns', None) ### otherwise pandas trunctates the columns
df = pd.DataFrame(Analysis_array,index=labels,columns=labels)
display(df)

### We need some equations for our linear cryptanalysis:

### 0C00 sub-> 0400 perm-> 0400 sub-> 0900 perm-> 4004 sub-> 9009
### with bias (4/16)**4

### This is used to derive an equation:

### Let P_1,...,P_16 denote the bits of the plaintext
### K^{i}_1,...,K^{i}_16 denote the bits of the keys
### U^{i} denote the state before the ith S-box
### and V^{i} the state after the ith S-box.

### We derive from the trail above the following equations:
### V^{1}_5 = P_4 + P_5 + K^{1}_4 + K^{1}_5
### V^{2}_4 + V^{2}_7 = V^{1}_5 + K^{2}_5
### V^{3}_0 + V^{3}_3 + V^{3}_12 + V^{3}_15 = V^{2}_4 + V^{2}_7 + K^{3}_1 + K^{3}_13

### We want to combine all of these to find the probabilistic relation before entering the
### last S-box.

### U^{4}_0 + U^{4}_3 + U^{4}_12 + U^{4}_15 = P_4 + P_5 + Sigma_K
### where Sigma_K = K^{1}_4 + K^{1}_5 + K^{2}_5 + K^{3}_1 + K^{3}_13 + K^{4}_0 + K^{4}_3 + K^{4}_12 + K^{4}_15

def eq(plain:str,test:str,ind_1:list[int],ind_2:list[int]) -> bool:
    p = 0
    t = 0
    for i in ind_1:
        p += int(plain[i])
    for j in ind_2:
        t += int(test[j])
    return (p + t) % 2 == 0

### We combine it with a second trail saying 7000 -> BOBB with bias (4/16)(6/16)**4
### We are finally ready to implement the attack:

k_1 = '1110011101100111'
k_2 = '0111011001111001'
k_3 = '0110011110010000'
k_4 = '0111100100000011'
k_5 = f'{0xf4f2:0>16b}'

start = []
gen_no = 10000 ### needs way more plaintexts than differential cryptanalysis
for _ in range(gen_no):
    P = ''.join(random.choice(['0','1']) for _ in range(16))
    out_P = SPN(P,k_1,k_2,k_3,k_4,k_5)
    start.append([P,out_P])

candidate_keys = []
for i in hex_list:
    for j in hex_list:
        for k in hex_list:
            candidate_keys.append(i + '0000' + k + j)
        ### combined tail is concentrated in blocks 1, 3 and 4
counter = [[0,0] for _ in candidate_keys]
#
#
for i in start:
    for j in candidate_keys:
        state = re.findall('.'*4,string_xor(i[1],j))
        test = inv_sub(state)
        plain = i[0]
        if eq(plain,test,[4,5],[0,3,12,15]):
            counter[candidate_keys.index(j)][0] += 1
        if eq(plain,test,[1,2,3],[0,2,3,8,10,11,12,14,15]):
            counter[candidate_keys.index(j)][1] += 1

g = lambda x : abs(x[1][0] - (gen_no//2)) + abs(x[1][1] - (gen_no//2))
Pair_list = [[a,b] for a,b in zip(candidate_keys,counter)]
Output = sorted(Pair_list,key = g,reverse=True)


print(f'Prediction for blocks 1, 3 and 4 of final key are {Output[0][0][:4]}...{Output[0][0][8:]}.')
print(f'Actual blocks are {k_5[:4]}...{k_5[8:]}.')

### It gets it correct. This approach takes a lot longer than differential cryptanalysis.

