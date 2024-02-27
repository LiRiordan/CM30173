
### Week 1 problems:
# In order to jump between numbers and letters we start the following class which we use in lots of
# further examples.
import string
class alpha_numeric():
    def __init__(self):
        self.index_char = [[i, c] for i, c in enumerate(string.ascii_uppercase)]
        self.numeric, self.alphabet = zip(*self.index_char)
        self.dict_1 = {self.numeric[i]: self.alphabet[i] for i in range(26)}
        self.dict_2 = {self.alphabet[i]: self.numeric[i] for i in range(26)}
        self.num_to_let = lambda x: self.dict_1[x]
        self.let_to_num = lambda x: self.dict_2[x]


## Trying to solve "by hand" some old school ciphers
## First cipher type: Caeser cipher

class Caeser_solver(alpha_numeric):
    def __init__(self,cipher):
        super().__init__()
        self.cipher = cipher
        for i in range(26):
            self.dict = {string.ascii_uppercase[j]:string.ascii_uppercase[(j+i)%26] for j in range(26)}
            self.caeser = lambda x : self.dict[x]
            self.test = ''
            for t in range(10):
                self.test += f'{self.caeser(self.cipher[t])}'
            print(f'shift by {i} produces {self.test}')
        corr = int(input('Which index should we use for the shift?: '))
        self.dict_fin = {string.ascii_uppercase[j]:string.ascii_uppercase[(j+corr)%26] for j in range(26)}
        self.final = ''
        self.caeser_swap = lambda x : self.dict_fin[x]
        for i in self.cipher:
            self.final += f'{self.caeser_swap(i)}'
        print(f'Your correctly shifted message should be read as follows: \n {self.final}')
    def shift(self,num,j):
        for i in range(len(num)):
            num[i] = (num[i] + j) % 26
        return num
    def list_to_alph(self,num):
        str = ''
        for i in range(len(num)):
            str += self.num_to_let(num[i])
        return str


### Now apply this to the cipher given in tutorials
# cipher_1 = 'WKHPDJLFZRUGVDUHVTXHDPLVKRVVLIUDJH'
# Caeser = Caeser_solver(cipher_1)

### Correctly determines shift should be by 23

#######################################################################################################

## Second cipher type: Permutation cipher
# Probably best to just do this by hand

## Third cipher type: Substitution cipher
# Here we want to try to use frequency analysis. Rather than defining a class to decode
# we define a class to help with frequency analysis.


### The following frequency analysis was stolen from wikipedia
frequency_ordering_in_text = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
frequencies_in_text = [12.7,9.1,8.2,7.5,7.0,6.7,6.3,6.1,6.0,4.3,4.0,2.8,2.8,2.4,2.4,2.2,2.0,2.0,1.9,1.5,0.98,0.77,0.15,0.15,0.095,0.074]


class Freq_analy(alpha_numeric):
    def __init__(self,cipher):
        super().__init__()
        self.cipher = cipher
        self.total_len = len(self.cipher)
        self.counter = [0 for _ in range(26)]
        for i in self.cipher:
            self.counter[self.let_to_num(i)] += 1
        str_1 = ''
        for i in range(13):
            str_1 += f'{self.num_to_let(i)} : {"{:.8f}".format(self.counter[i]/self.total_len)} ---- '
        str_2 = ''
        for i in range(13,26):
            str_2 += f'{self.num_to_let(i)} : {"{:.8f}".format(self.counter[i]/self.total_len)} ---- '
        self.start_pair = [[c,f] for c,f in zip(string.ascii_uppercase,self.counter)]
        self.start_pair = sorted(self.start_pair, key = lambda x:x[1], reverse=True)
        self.begin, _ = zip(*self.start_pair)
        self.swap_dict = {self.begin[i]:frequency_ordering_in_text[i] for i in range(26)}
        self.swap = lambda x : self.swap_dict[x]
        self.final = ''
        for i in self.cipher:
            self.final += f'{self.swap(i)}'
        print(f'Your suggested substitution based on frequency analysis should be: \n'
              f'{self.final}')

# cipher_3 = 'AGBAPZTGELGPTIPMGHQCGAECHZFVCEXXGLYIGHEULTQATQHPUFEUYGZZEVGUYHGUYIPUYIGQUGYIPYEAYIGFNKTYYCEGLYIGFSQKZLEUMGUYPSEXIGCYIPYUQQUGSQKZLDCGPO'
# Substitution = Freq_analy(cipher_3)
### message is short enough that this does a terrible job. Only gets the top two most frequent letters right.

### We will try to decipher a substitution of the first 5 pages of Harry Potter using frequency analysis.
#import os
# root = r'C:\Users\lrr27\PycharmProjects\CM30173_Tutorials'
# file = r'substitute.txt'
# import re
# with open(os.path.join(root,file)) as text:
#     substitute_text = text.read()
# long_sub_cipher = re.sub('[^A-Za-z]+','',substitute_text).upper()
# with open(os.path.join(root,'real.txt')) as correct:
#     corrected = correct.read()
# original = re.sub('[^A-Za-z]+','',corrected).upper()
# Longer_sub = Freq_analy(long_sub_cipher)
# print(original)
# print(len(original))
### Frequency analysis can't even do that great a job on th first 5 pages of harry potter




















