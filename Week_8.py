### Week_8 we're considering how some of the maths we've already seen
### interacts with RSA.
import math

from numba import njit

@njit
def inverse(k: int, n: int) -> int:
    """Invert a number k modulo n (when possible)."""
    t = k % n
    for i in range(n):
        if (t * i) % n == 1:
            return i
    else:
        print("Not invertible")

@njit
def chinese_remainder(vals: list[int], modular: list[int]) -> list[int]:
    """Equations x = a_i mod (n_i). vals records the a_i and modular records the n_i.
    We will assume the n_i are all pairwise coprime."""
    n_prod = 1
    for i in modular:
        n_prod *= i
    m_list = [n_prod//i for i in modular]
    y_list = [inverse(m_list[i], modular[i]) for i in range(len(modular))]
    t = 0
    for i in range(len(modular)):
        t += (vals[i] * m_list[i] * y_list[i]) % n_prod
    return [t,n_prod]


plaintext = 19
keys = [[26, 3], [33, 3], [35, 3]]
modular = [keys[i][0] for i in range(len(keys))]
n_prod  = 1
for i in modular:
    n_prod *= i
ciphers = []
for i in range(len(keys)):
    p = plaintext + i + 1 ### this is the padding from the question
    ciphers.append(p**keys[i][1] % keys[i][0])
from scipy.special import comb
polys = []
for i in range(len(keys)):
    t = keys[i][1]
    coeffs = []
    for j in range(t + 1):
        coeffs.append((((i + 1) ** (t - j)) * comb(t, j, exact=True)) % keys[i][0])
    coeffs[0] = (coeffs[0] - ciphers[i]) % keys[i][0]
    polys.append(coeffs)

scalar = []
for i in range(len(keys)):
    vals = [0 for _ in range(len(keys))]
    vals[i] = 1
    scalar.append(chinese_remainder(vals, modular))

top = max([len(coeffs) for coeffs in polys])
polynomial = [0 for _ in range(top)]
for i in range(len(polys)):
    for j in range(len(polys[i])):
        polynomial[j] += scalar[i][0]*polys[i][j]
for i in range(len(polynomial)):
    polynomial[i] = polynomial[i] % n_prod
output = ''
for i in range(len(polynomial) - 1):
    output += f'{polynomial[i]}X**{i} + '
output += f'{polynomial[-1]}X**{top-1}'
# print(output)

### Coppersmith/Howgrave-Graham means that in polynomial time we can recover the
### root x = plaintext since it is sufficiently small. In particular we can recover
### the plaintext.

###Shanks algorithm:

def shanks_algorithm(n: int, alpha: int, beta: int) -> int:
    m = math.ceil(n**0.5)
    inv_alp = inverse(alpha, n)
    l1 = [[0,1]]
    l2 = [[0,beta]]
    for j in range(1,m):
        l1.append([j, ((alpha**m)*l1[-1][1])%n])
        l2.append([j, (inv_alp*l2[-1][1])%n])
    for a in l1:
        for b in l2:
            if a[-1] == b[-1]:
                return (a[0]*m + b[0]) % n


alpha = 106
beta = 12375
n = 24691

j = shanks_algorithm(n, alpha, beta)
print(j)
print((alpha**j) % n)















