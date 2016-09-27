#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
#	Python AES Implementation
#  aes.py
#  
#  Copyright 2016 Mauricio <mauricio@dell-laptop>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
import json
from pprint import pprint

with open('_maps.json') as data_file:
	boxes = json.load(data_file)
	
sbox = boxes['SBOX']

rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb]

def aes128(block, cipher_key):
	cipher_block = ''
	state = build_state_matrix(block)
	key   = build_key_matrix(cipher_key)
	generate_subkeys(key)
	return cipher_block
	
def generate_subkeys(key):
	W = [[]] * 44
	#r = [10 ** ((i-4)/4) for i in xrange(4, 45)]
	#rcon = [0]*44
	#print "r", r
	# Fill W with the four first columns
	round_key_index = 0
	round_keys = [[]]*11
	round_keys[round_key_index] = key
	W[0] = [key[j][0] for j in xrange(4)]
	W[1] = [key[j][1] for j in xrange(4)]
	W[2] = [key[j][2] for j in xrange(4)]
	W[3] = [key[j][3] for j in xrange(4)]
	print '--------------------------------- Key Generation -------------------------------------'
	print ' i | W[i-1] | rot_word | sub_word | rcon[i/4] |   xor   |  W[i-4]  |   W[i]'
	print '--------------------------------------------------------------------------------------'
	for i in xrange(4, 44):
		if i % 4 == 0:
			if i >= 8:
				round_keys[round_key_index] = round_key
			round_key_index += 1
			rot = rot_word(W[i-1])
			sub = sub_word(rot)
			new = hex(int(sub[0], 16) ^ rcon[i/4])[2:]
			new_sub = [new] + sub[1:]
			W[i] = xor(W[i - 4], new_sub)
			
			round_key = [W[i]]
			print '--------------------------------------------------------------------------------------'
			print '{0:2d}  {1}  {2}   {3:8}      {4:8} {5:8}  {6:8}   {7}'.format(i, ''.join(W[i-1]), ''.join(rot), ''.join(sub), hex(rcon[i/4]), ''.join(new_sub), ''.join(W[i-4]), ''.join(W[i]))
		else:
			W[i] = xor(W[i - 4], W[i - 1])
			round_key.append(W[i])
			print '{0:2d}  {1}  {2:8}   {3:8}      {4:8} {5:8}  {6:8}   {7}'.format(i, ''.join(W[i-1]), '', '', '', '', ''.join(W[i-4]), ''.join(W[i]))
		round_keys[-1] = round_key
		
	for k in xrange(1, len(round_keys)):
		dump_key = transpose(round_keys[k])
		round_keys[k] = dump_key
	print 'round_keys'
	pprint(round_keys)
	return round_keys
			
def put_leading_zeroes(d):
	return '{:08d}'.format(d)

# Makes a cyclic shift by n positions on the array l
def rot_word(l):
	return l[1:] + l[:1]

def sub_word(C):
	S = []
	for c in C:
		if c[0] == ' ': c[0] = '0'
		if c[1] == ' ': c[1] = '0'
		S.append(sbox[c[0]][c[1]])
	return S
	
# Galois Multiplication
def galoisMult(a, b):
    p = 0
    hiBitSet = 0
    for i in range(8):
        if b & 1 == 1:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256
	
def T(C):
	return C
	
def xor(A, B):
	result = []
	for i, j in zip(A, B):
		result.append(hex(int(i, 16) ^ int(j, 16))[2:].zfill(2))
	return result
		
		
	
def build_state_matrix(block):
	raw_state = list(chunks(block, 4))
	state = transpose(raw_state)
	print 'state:'
	pprint(state)
	return state
	
def build_key_matrix(cipher_key):
	raw_key = list(chunks(cipher_key, 4))
	key = transpose(raw_key)
	print 'key:'
	pprint(key)
	return key
	
def transpose(M):
	return [list(i) for i in zip(*M)]
	

# Yield successive n-sized chunks from l.
def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]

# Converts strings into a list of hexadecimal values
def str_to_hex(s):
	#return [hex(ord(c)) for c in s]
	return [c.encode('hex') for c in s]
	
# Converts a list of hexadecimal numbers to a string
def hex_to_str(H):
	s = ''
	#for h in H: s = s + h.replace('0x', '').decode('hex')
	for h in H: s += h
	return s.decode('hex')
	
# Fix the data block
def fix_block(b):
	# 16 bytes = 128 bits
	lb = len(b)
	if lb == 16: return b
	elif lb < 16:
		for i in xrange(16 - lb):
			b = ['00'] + b
	return b

# Split the plain text in blocks of 16 bytes
def process_plaintext(plaintext):
	if len(plaintext) <= 16:
		return [fix_block(str_to_hex(plaintext))]
	hex_repr   = str_to_hex(plaintext)
	blocks     = list(chunks(hex_repr, 16))
	blocks[-1] = fix_block(blocks[-1])
	for j in xrange(len(blocks)):
		print_list('blocks['+str(j)+']', blocks[j], 2)
	return blocks

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

# Main program
def main(args):
	print 'ADVANCED ENCRYPTION STANDARD (AES)'
	#plaintext = raw_input('Please enter the message to encrypt: ')
	plaintext = 'AES es muy facil'
	blocks = process_plaintext(plaintext)
	#key = raw_input('Please enter the cipher key: ')
	cipher_key = ['2b', '7e', '15', '16', '28', 'ae', 'd2', 'a6', 'ab', 'f7', '15', '88', '09', 'cf', '4f', '3c']
	print_list('cipher_key:', cipher_key, 4)
	cipher_block = aes128(blocks[0], cipher_key)
	return 0

if __name__ == '__main__':
	import sys
	sys.exit(main(sys.argv))





	
	
	
