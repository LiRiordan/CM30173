### Week 3: Differential cryptanalysis of SPNs
import random
import string
from Week_2 import string_xor, SPN, decorator
import re

sub_list = [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15]
perm_list = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
hex_list = ['{0:04b}'.format(int(t,16)) for t in string.hexdigits[:16].upper()]
@decorator
def inv_sub(x):
    '''This will be the inverse of the substitution function used in the SPN'''
    hex_dict = {hex_list[sub_list[i]]:hex_list[i] for i in range(16)}
    return hex_dict[x]


# In differential cryptanalysis we study the effect that the cipher has
# on the difference between two inputs.
import numpy as np
def distribution_array(func):
    """This will be an array which records the differences between outputs, based on differences between inputs"""
    B = np.zeros([16,16])
    for i in hex_list:
        for j in hex_list:
            x_diff = string_xor(i,j)
            y_diff = string_xor(func(i),func(j))
            x_index = hex_list.index(x_diff)
            y_index = hex_list.index(y_diff)
            B[x_index,y_index] += 1
    return B


def sub(x):
    '''Redefined substitution without the decorator.
    sub : str -> str
    len(4) -> len(4).'''
    sub_dict = {hex_list[i]:hex_list[sub_list[i]] for i in range(16)}
    return sub_dict[x]

# print(distribution_array(sub))
### At this point often helpful to draw permutation
### Possible differential trail '1110|0000|0000|0000' -> '0000|0110|0110|0000' (can be found
### in lecturer's notes)
### We will also use one found by exploiting symmetries of the permutation given by 00b0 -> 9009


### First round will be: {0x00b0:0>16b} -> {0x9009:0>16b}
### This happens with the same probability as the one given in the course: 81/4096
X_diff = f'{0x00b0:0>16b}'
Y_diff = f'{0x9009:0>16b}'
### We now implement the attack:
k_1 = '1110011101100111'
k_2 = '0111011001111001'
k_3 = '0110011110010000'
k_4 = '0111100100000011'
k_5 = f'{0xe4f2:0>16b}'  ###this is the bit we will guess
### We start by generating a large number of plaintexts of length 16, their difference partners
### and their cipher differences.
# start = []
# for _ in range(1000):
#     P = ''.join(random.choice(['0','1']) for _ in range(16))
#     Q = string_xor(P,X_diff)
#     out_P = SPN(P,k_1,k_2,k_3,k_4,k_5)
#     out_Q = SPN(Q,k_1,k_2,k_3,k_4,k_5)
#     start.append([P,Q,out_P,out_Q])
#
# candidate_keys_one = []
# for i in hex_list:
#     for j in hex_list:
#         candidate_keys_one.append(i + '00000000' + j)
#         # tail is concentrated in blocks 1 and 4
# counter_one = [0 for _ in candidate_keys_one]


# for i in start:
#     for j in candidate_keys_one:
#         state_1 = re.findall('.'*4,string_xor(i[2],j))
#         state_2 = re.findall('.'*4,string_xor(i[3],j))
#         test_1 = inv_sub(state_1)
#         test_2 = inv_sub(state_2)
#         test_out = string_xor(test_1,test_2)
#         if test_out == Y_diff:
#             counter_one[candidate_keys_one.index(j)] += 1
#
# Output = [[a,b] for a,b in zip(candidate_keys_one,counter_one)]
# Output = sorted(Output,key = lambda x:x[1], reverse = True)


### We now perform an attack using the other differential trail
### e000 -> 0660 with probability 81/4096

# x_2_diff = f'{0xe000:0>16b}'
# y_2_diff = f'{0x0660:0>16b}'
# #
# start_2 = []
# for _ in range(1000):
#     P = ''.join(random.choice(['0','1']) for _ in range(16))
#     Q = string_xor(P,x_2_diff)
#     out_P = SPN(P,k_1,k_2,k_3,k_4,k_5)
#     out_Q = SPN(Q,k_1,k_2,k_3,k_4,k_5)
#     start_2.append([P,Q,out_P,out_Q])

# candidate_keys_two = []
# for i in hex_list:
#     for j in hex_list:
#         candidate_keys_two.append('0000' + i  + j + '0000')
#         # tail is concentrated in blocks 2 and 3
# counter_two = [0 for _ in candidate_keys_two]
# for i in start_2:
#     for j in candidate_keys_two:
#         state_1 = re.findall('.'*4,string_xor(i[2],j))
#         state_2 = re.findall('.'*4,string_xor(i[3],j))
#         test_1 = inv_sub(state_1)
#         test_2 = inv_sub(state_2)
#         test_out = string_xor(test_1,test_2)
#         if test_out == y_2_diff:
#             counter_two[candidate_keys_two.index(j)] += 1
#
# Output_two = [[a,b] for a,b in zip(candidate_keys_two,counter_two)]
# Output_two = sorted(Output_two,key = lambda x:x[1], reverse = True)

# print(f'The final round key is {k_5}. The differential cryptanalysis suggests targeted key_bits \n')
# print(f'00b0 -> 9009                                 e000 -> 0660 \n')
# print(f'1:{Output[0][0]}                             1:{Output_two[0][0]} \n')
# print(f'2:{Output[1][0]}                             2:{Output_two[1][0]} \n')
# print(f'3:{Output[2][0]}                             3:{Output_two[2][0]}')
#
# key_1 = Output[0][0][0:4]
# key_2 = Output[0][0][12:]
# key_3 = Output_two[0][0][4:12]
# print(f'predicted final round key is {key_1 + key_3 + key_2}')

### This step only works
### because we have found two differential trails which cover all possible 4-bit divisions.




