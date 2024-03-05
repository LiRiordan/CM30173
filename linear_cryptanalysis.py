import string
from Week_2 import SPN, string_xor, decorator, pi_sub
from Week_3 import sub
import pandas as pd
import numpy as np
from IPython.display import display
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







