import math
from crypto_utils import char_to_index, index_to_lower_char, index_to_upper_char

MOD = 26

def mod(n, m=MOD): 
    return ((n % m) + m) % m

def parse_square_matrix(text, size=None):
    tokens = text.replace(',', ' ').split()
    if not tokens:
        raise ValueError("Matrix input is empty.")
    if size is None or size == '':
        root = int(math.isqrt(len(tokens)))
        size = root
    else:
        size = int(size)
    if len(tokens) != size * size:
        raise ValueError(f"Expected {size*size} values.")
    matrix = []
    it = iter(tokens)
    for _ in range(size):
        matrix.append([int(next(it)) for _ in range(size)])
    return matrix

def parse_key_text(text, size=None):
    indices = [char_to_index(c) for c in text if char_to_index(c) != -1]
    if not indices:
        raise ValueError("Key text must contain letters a-z.")
    if size is None or size == '':
        size = int(math.isqrt(len(indices)))
    else:
        size = int(size)
    needed = size * size
    if len(indices) < needed:
        indices += [char_to_index('x')] * (needed - len(indices))
    else:
        indices = indices[:needed]
    matrix = []
    it = iter(indices)
    for _ in range(size):
        matrix.append([next(it) for _ in range(size)])
    return matrix

def determinant(m):
    n = len(m)
    if n == 1: return m[0][0]
    if n == 2: return m[0][0]*m[1][1] - m[0][1]*m[1][0]
    det = 0
    for c in range(n):
        minor = [row[:c] + row[c+1:] for row in m[1:]]
        det += ((-1)**c) * m[0][c] * determinant(minor)
    return det

def transpose(m):
    return [[m[j][i] for j in range(len(m))] for i in range(len(m[0]))]

def cofactor_matrix(m):
    n = len(m)
    if n == 1: return [[1]]
    cof = [[0]*n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            minor = [row[:c] + row[c+1:] for row in (m[:r] + m[r+1:])]
            cof[r][c] = ((-1)**(r+c)) * determinant(minor)
    return cof

def extended_gcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_r, old_s

def mod_inverse(a, m=MOD):
    g, x = extended_gcd(mod(a, m), m)
    if g != 1: raise ValueError("Matrix is not invertible mod 26.")
    return mod(x, m)

def inverse_matrix_mod26(m):
    det_inv = mod_inverse(determinant(m), 26)
    adj = transpose(cofactor_matrix(m))
    return [[mod(val * det_inv, 26) for val in row] for row in adj]

def encrypt_hill(plaintext, matrix):
    n = len(matrix)
    indices = [char_to_index(c) for c in plaintext if char_to_index(c) != -1]
    while len(indices) % n != 0: indices.append(char_to_index('x'))
    res, blocks = "", []
    for i in range(0, len(indices), n):
        vec = indices[i:i+n]
        block_info = {'vec': vec, 'products': [], 'sums': [], 'sums_mod': [], 'letters': []}
        for j in range(n):
            prods = [vec[k] * matrix[k][j] for k in range(n)]
            s = sum(prods); s_mod = mod(s); char = index_to_upper_char(s_mod)
            block_info['products'].append(prods); block_info['sums'].append(s)
            block_info['sums_mod'].append(s_mod); block_info['letters'].append(char)
        blocks.append(block_info)
        res += "".join(block_info['letters'])
    return {'text': res, 'matrix': matrix, 'blocks': blocks}

def decrypt_hill(ciphertext, matrix):
    n = len(matrix)
    
    # Calculate intermediate steps for display
    det_val = determinant(matrix)
    det_mod26 = mod(det_val)
    det_inv = mod_inverse(det_val, 26)
    cof = cofactor_matrix(matrix)
    adj = transpose(cof)
    inv_m = [[mod(val * det_inv, 26) for val in row] for row in adj]
    
    indices = [char_to_index(c) for c in ciphertext if char_to_index(c) != -1]
    res, blocks = "", []
    for i in range(0, len(indices), n):
        vec = indices[i:i+n]
        block_info = {'vec': vec, 'products': [], 'sums': [], 'sums_mod': [], 'letters': []}
        for j in range(n):
            prods = [vec[k] * inv_m[k][j] for k in range(n)]
            s = sum(prods); s_mod = mod(s); char = index_to_lower_char(s_mod)
            block_info['products'].append(prods); block_info['sums'].append(s)
            block_info['sums_mod'].append(s_mod); block_info['letters'].append(char)
        blocks.append(block_info); res += "".join(block_info['letters'])
        
    return {
        'text': res, 
        'matrix': matrix, 
        'inv_matrix': inv_m, 
        'cofactor_matrix': cof,
        'adjugate_matrix': adj,
        'det': det_val, 
        'det_mod': det_mod26, 
        'det_inv': det_inv, 
        'blocks': blocks
    }