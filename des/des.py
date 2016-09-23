import random, json
from pprint import pprint

PERM = 'perm'
INITIAL = 'initial'

with open('des_maps.json') as data_file:
	transforms = json.load(data_file)

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

# Generates a random array of 64 bits
def generate_random_key():
	random_key = []
	for i in range(56):
		random_key.append(random.randint(0, 1))
	return random_key

# The des encryption algortihm for a single block and 128-length key.
def des_encrypt(block, key):
	pblock = initial_permutation(block)
	print "perm_block", pblock
	print block

# Makes the initial permutation (IP) on the plaintext block.
def initial_permutation(block):
	perm_block = ['e']*64
	IP = transforms[PERM][INITIAL]
	for i in range(64):
		print i, IP[i] - 1 
		perm_block[i] = block[IP[i] - 1]
	return perm_block
#               -------- Example from the slides --------

my_key = convert_to_bits(1, 4) + convert_to_bits(3, 4) + convert_to_bits(3, 4) + \
	convert_to_bits(4, 4) + convert_to_bits(5, 4) + convert_to_bits(7, 4) + \
	convert_to_bits(7, 4) + convert_to_bits(9, 4) + convert_to_bits(9, 4) + \
	convert_to_bits(12, 4) + convert_to_bits(12, 4) + convert_to_bits(13, 4) + \
	convert_to_bits(14, 4) + convert_to_bits(15, 4) + convert_to_bits(15, 4) + \
	convert_to_bits(1, 4)

my_block = convert_to_bits(0, 4) + convert_to_bits(1, 4) + convert_to_bits(2, 4) + \
	convert_to_bits(3, 4) + convert_to_bits(4, 4) + convert_to_bits(5, 4) + \
	convert_to_bits(6, 4) + convert_to_bits(7, 4) + convert_to_bits(8, 4) + \
	convert_to_bits(9, 4) + convert_to_bits(10, 4) + convert_to_bits(11, 4) + \
	convert_to_bits(12, 4) + convert_to_bits(13, 4) + convert_to_bits(14, 4) + \
	convert_to_bits(15, 4)
	
print "my_block =", my_block
print "my_key =", my_key
des_encrypt(my_block, my_key)

