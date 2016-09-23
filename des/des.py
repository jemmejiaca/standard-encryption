import random, json
from pprint import pprint

PERM = 'perm'
INITIAL = 'initial'

with open('des_maps.json') as data_file:
	transforms = json.load(data_file)

IP = transforms[PERM][INITIAL]
PC1 = transforms[PERM]["1"]
PC2 = transforms[PERM]["2"]

# Converts decimals to bits
def convert_to_bits(n, pad):
    result = []
    while n > 0:
        if n % 2 == 0:
            result = [0] + result
        else:
            result = [1] + result
        n = n / 2
    while len(result) < pad:
        result = [0] + result
    return result

# Converts strings to binary
def string_to_bits(s):
    result = []
    for c in s:
        result = result + convert_to_bits(ord(c), 8)
    return result

def dec_to_hex(n):
	return hex(n)
	
# use: hex_to_dec('AF')
def hex_to_dec(h):
	return int(h, 16);

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]
        
# Print lists with a space every j elements with a message as prefix.
def print_list(msg, l, j):
	left_spaces = 23
	msg_len = len(msg)
	if j == 0: 
		print msg + (' ' * (left_spaces - msg_len)), "".join(str(x) for x in l)
		return
	s = ''
	c = 0
	for i in l:
		if c % j == 0 and c > 0: s = s + ' '
		s = s + str(i)
		c = c + 1
	print msg + (' ' * (left_spaces - msg_len)), s

# Generates a random array of 64 bits
def generate_random_key():
	random_key = []
	for i in range(56):
		random_key.append(random.randint(0, 1))
	return random_key

# The des encryption algortihm for a single block and 128-length key.
def des_encrypt(block, key):
	print "-------------------DES Encryption-------------------"
	print_list('block =', block, 8)
	print_list('key =', key, 8)
	
	pblock = initial_permutation(block)
	create_subkeys(key)

# Makes the initial permutation (IP) on the plaintext block.
def initial_permutation(block):
	perm_block = ['e'] * 64
	for i in range(64):
		#print i, IP[i] - 1 
		perm_block[i] = block[IP[i] - 1]
	print_list('IP(block) =', perm_block, 8)
	return perm_block
	
def create_subkeys(key):
	subkeys = [[]] * 17
	C = [['c'] * 28] * 17  # this is begging for a more elegant form.
	D = [['d'] * 28] * 17
	
	pkey = pc1(key)
	
	C[0] = pkey[0:28]
	D[0] = pkey[28:56]
	print_list('C[0] ', C[0], 7)
	print_list('D[0] ', D[0], 7)
	subkeys[0] = pc2(C[0], D[0], 0) # WARNING: this subkey is never used
	
	for i in xrange(1, 17):
		msg_c = "C["+str(i)+"] ="
		msg_d = "D["+str(i)+"] ="
		if i in [1, 2, 9, 16]:
			C[i] = left_shift(C[i-1], 1)
			D[i] = left_shift(D[i-1], 1)
		else:
			C[i] = left_shift(C[i-1], 2)
			D[i] = left_shift(D[i-1], 2)
		print_list(msg_c, C[i], 0)
		print_list(msg_d, D[i], 0)
		subkeys[i] = pc2(C[i], D[i], i)
	
	
def left_shift(l, n):
	return l[n:] + l[:n]
	
def pc1(key):
	pkey = ['e'] * 56
	for i in range(56):
		pkey[i] = key[PC1[i] - 1]
	print_list('PC1(key) =', pkey, 7)
	return pkey
	
def pc2(c, d, k):
	presubkey = c + d
	psubkey = ['e'] * 48
	for i in range(48):
		psubkey[i] = presubkey[PC2[i] - 1]
	msg = 'PC2(C[' + str(k) +']D[' + str(k)+']): k' + str(k) + ' ='
	print_list(msg, psubkey, 6)
	return psubkey
	

#               -------- Example from the slides --------

my_key = convert_to_bits(1, 4) + convert_to_bits(3, 4) + convert_to_bits(3, 4) + \
	convert_to_bits(4, 4) + convert_to_bits(5, 4) + convert_to_bits(7, 4) + \
	convert_to_bits(7, 4) + convert_to_bits(9, 4) + convert_to_bits(9, 4) + \
	convert_to_bits(11, 4) + convert_to_bits(11, 4) + convert_to_bits(12, 4) + \
	convert_to_bits(13, 4) + convert_to_bits(15, 4) + convert_to_bits(15, 4) + \
	convert_to_bits(1, 4)

my_block = convert_to_bits(0, 4) + convert_to_bits(1, 4) + convert_to_bits(2, 4) + \
	convert_to_bits(3, 4) + convert_to_bits(4, 4) + convert_to_bits(5, 4) + \
	convert_to_bits(6, 4) + convert_to_bits(7, 4) + convert_to_bits(8, 4) + \
	convert_to_bits(9, 4) + convert_to_bits(10, 4) + convert_to_bits(11, 4) + \
	convert_to_bits(12, 4) + convert_to_bits(13, 4) + convert_to_bits(14, 4) + \
	convert_to_bits(15, 4)

des_encrypt(my_block, my_key)

