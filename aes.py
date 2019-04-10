#!/usr/bin/python
import sys
import random

#Substitution box used for Encryption and Key generation
sbox = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
	[0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
	[0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
	[0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
	[0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
	[0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
	[0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
	[0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
	[0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
	[0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
	[0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
	[0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
	[0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
	[0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
	[0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

#Substitution box used for decryption
inv_sbox = [[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
	    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
	    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
	    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
	    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
	    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
	    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
	    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
	    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
	    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
	    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
            [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
            [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
            [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
            [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]]

key = []     #Original Key
cipher=[]
words=[[0,0,0,0]] *44	#Expanded key

#Partition a given hexadecimal '0xPQ' into row index 'P' and coloumn index 'Q'
def partitionHexadecimal(integer):
	return divmod(integer, 0x10)

#Return SBox value at a particular row and coloumn
def getSBoxSubstitution(row,col):
	return sbox[row][col]

#Return Inverse SBox value at a particular row and coloumn
def getInverseSBoxSubstitution(row,col):
	return inv_sbox[row][col]

#convert a string message into a 4*4 matrix of hexadecimals
def textToMatrix(msg):
	if len(msg) < 16:
		print("128 bits or 16 bytes of data required.")
		return None
	matrix = [[0]*4 for i in range(4)]
	pos = 0
	for x in range(4):
		for y in range(4):
			matrix[y][x] = ord(msg[pos]) & 0xFF
			pos += 1
	return matrix

#Convert a given hexadecimal message into a matrix
def hexToMatrix(msg):
	matrix = [[0]*4 for i in range(4)]
	pos = 0
	for x in range(4):
		for y in range(4):
			matrix[y][x] = msg[pos]
			pos += 1
	return matrix

#Convert a list of hexadecimals into a String of hexadecimals
def hexListToString(hexList):
        hexString = ''
        for byte in hexList:
                hexString += '{:0>2}'.format((hex(byte)[2:]))
        return hexString

#Perform XOR operation on 2 Matrix
def xorMatrix (textMatrix,keyMatrix):
	result = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
	x=0
	while(x<4):
		y=0
		while(y<4):
			result[x][y] = textMatrix[x][y] ^ keyMatrix[x][y]
			y=y+1
		x=x+1
	return result

#Return respective substitution value for a given hexadecimal No.
def forwardPartitionAndSbstitution( number):
	row,col=partitionHexadecimal(number)
	number = getSBoxSubstitution(row,col)
	return number

#Substitute each byte of a matrix according to the SBox
def forwardSubstitution ( matrix ):
	for i in range(4):
		for j in range(4):
			matrix[i][j] = forwardPartitionAndSbstitution(matrix[i][j])
	return matrix

#Substitute each byte of a matrix according to the Inverse SBox
def backwardSubstitution (matrix):
	for i in range(4):
		for j in range(4):
			row,col=partitionHexadecimal(matrix[i][j])
			matrix[i][j] = getInverseSBoxSubstitution(row,col)
	return matrix

#Perform Shift row operation for the Encrytion
def forwardShiftRow (matrix):
	for x in range(1,4):
		matrix[x]=matrix[x][x:] + matrix[x][:x]
	return matrix

#Perform reverse Shift Operation
def backwardShiftRow (matrix):
	for x in range(1,4):
		matrix[x]=matrix[x][-x:] + matrix[x][:-x]
	return matrix

#multiply a given byte with 0x02 in GF 2^8
def mulTwo_x(byte):
	if (byte >> 7) & 0x01 == 1:
		byte = byte << 1
		byte= byte ^ 0x1B
	else :
		byte = byte << 1
	return byte & 0xFF

#perform Mix coloumn for encrytion
def forwardMixColoumn (matrix):
	state = [[matrix[i][j] for j in range(4)] for i in range(4)]
	for j in range(4):
		state[0][j] = mulTwo_x(matrix[0][j]) ^ (mulTwo_x(matrix[1][j]) ^ matrix[1][j]) ^ matrix[2][j] ^ matrix[3][j]
	for j in range(4):
		state[1][j] = matrix[0][j] ^ mulTwo_x(matrix[1][j]) ^ (mulTwo_x(matrix[2][j]) ^ matrix[2][j]) ^ matrix[3][j]
	for j in range(4):
		state[2][j] = matrix[0][j] ^ matrix[1][j] ^ mulTwo_x(matrix[2][j]) ^ (mulTwo_x(matrix[3][j]) ^ matrix[3][j])
	for j in range(4):
		state[3][j] = (mulTwo_x(matrix[0][j]) ^ matrix[0][j]) ^ matrix[1][j] ^ matrix[2][j] ^ mulTwo_x(matrix[3][j])
	matrix = state
	return matrix

#perform Mix coloumn for decrytion
def backwardMixColoumn (matrix):
	state = [[matrix[i][j] for j in range(4)] for i in range(4)]
	for j in range(4):
		state[0][j] = (mulTwo_x(mulTwo_x((mulTwo_x(matrix[0][j]) ^ matrix[0][j]))^ matrix[0][j])) ^ (mulTwo_x((mulTwo_x(mulTwo_x(matrix[1][j])) ^ matrix[1][j]))^matrix[1][j]) ^ (mulTwo_x(mulTwo_x((mulTwo_x(matrix[2][j]) ^ matrix[2][j]))) ^ matrix[2][j]) ^ (mulTwo_x(mulTwo_x(mulTwo_x(matrix[3][j])))^matrix[3][j])
	for j in range(4):
		state[1][j] = (mulTwo_x(mulTwo_x(mulTwo_x(matrix[0][j])))^matrix[0][j]) ^ (mulTwo_x(mulTwo_x((mulTwo_x(matrix[1][j]) ^ matrix[1][j]))^ matrix[1][j])) ^ (mulTwo_x((mulTwo_x(mulTwo_x(matrix[2][j])) ^ matrix[2][j])) ^ matrix[2][j]) ^ (mulTwo_x(mulTwo_x((mulTwo_x(matrix[3][j]) ^ matrix[3][j])))^matrix[3][j])
	for j in range(4):
		state[2][j] = (mulTwo_x(mulTwo_x((mulTwo_x(matrix[0][j]) ^ matrix[0][j])))^matrix[0][j]) ^ (mulTwo_x(mulTwo_x(mulTwo_x(matrix[1][j])))^matrix[1][j]) ^ (mulTwo_x(mulTwo_x((mulTwo_x(matrix[2][j]) ^ matrix[2][j])) ^ matrix[2][j])) ^ (mulTwo_x((mulTwo_x(mulTwo_x(matrix[3][j])) ^ matrix[3][j]))^matrix[3][j])
	for j in range(4):
		state[3][j] = (mulTwo_x((mulTwo_x(mulTwo_x(matrix[0][j])) ^ matrix[0][j]))^matrix[0][j]) ^ (mulTwo_x(mulTwo_x((mulTwo_x(matrix[1][j]) ^ matrix[1][j]))) ^ matrix[1][j]) ^ (mulTwo_x(mulTwo_x(mulTwo_x(matrix[2][j])))^matrix[2][j])  ^ (mulTwo_x(mulTwo_x((mulTwo_x(matrix[3][j]) ^ matrix[3][j])) ^ matrix[3][j]))
	matrix = state
	return matrix
	
#Expansion of key
def expandKey (keyMatrix):
	rc = [0]*11	#round constant to be used in key expansion at each round
	rc[1]=0x1
	for i in range(2,11):
		rc[i]= mulTwo_x(rc[i-1])
	# Round 0 key is same as original key
	words[0]=[keyMatrix[i][0] for i in range(4)]
	words[1]=[keyMatrix[i][1] for i in range(4)]
	words[2]=[keyMatrix[i][2] for i in range(4)]
	words[3]=[keyMatrix[i][3] for i in range(4)]
	c=4	# current coloumn to work upon
	for i in range(1,11):
		# take just previous coloumn for xor
		temp = [words[c-1][i] for i in range(4)]
		# shift operation
		temp = temp[1:] + temp[:1]
		#substitution
		temp = list(map(lambda x  : forwardPartitionAndSbstitution(x), temp))
		#XOR with round constant
		temp[0] = (temp[0] ^ rc[i])
		#xor with 4th previous coloumn (word)
		for j in range(4):
			words[c] = list(map(lambda x,y : x^y, temp, words[c-4]))
			temp = words[c]
			c += 1
	
# Return a group of key words required for a particular roundof encrytion
def roundKey (roundNo):
	x=roundNo * 4
	mat=words[x:x+4]
	mat2=[[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
	for i in range (4):
		for j in range(4):
			mat2[i][j]=mat[j][i]
	return (mat2)
	
# Return a group of key words required for a particular roundof decrytion
def decryptionRoundKey (roundNo):
	return roundKey(10-roundNo)

#Take key in hexadecimal format as input
def keyInput():
	keyInHexString = input('Enter Key in Hex : ')
	while len(keyInHexString) != 32:
		print('Key should be 16 bytes long')
		keyInHexString = input('Enter Key in Hex : ')
	for i in range(0,len(keyInHexString), 2):
		key.append(int(keyInHexString[i:i+2], base=16))
	if len(key) != 16:
		print('Key input not correct\nexiting system ...')
		sys.exit()
	return key
def cipherTextInput():
	kInHexString = input('Enter ciphertext in Hex : ')
	while len(kInHexString) != 32:
		print('Ciphertext should be 16 bytes long')
		kInHexString = input('Enter Ciphertext in Hex : ')
	for i in range(0,len(kInHexString), 2):
		cipher.append(int(kInHexString[i:i+2], base=16))
	if len(cipher) != 16:
		print('Ciphertext input not correct\nexiting system ...')
		sys.exit()
	return cipher	

#print a list in hexadecimal format
def printList(lst):
        for x in range(len(lst)): 
            print (hex(lst[x]), end = '   ')
            
#print a matrix in well-adjusted format
def printMatrix(matrix):
        
	printList(matrix[0])
	print("\t")
	printList(matrix[1])
	print("\t")
	printList(matrix[2])
	print("\t")
	printList(matrix[3])
	print("\t")
	print()
	
#main
toDoChoice = input("What do you want to do?\n1.Encryption\n2.Decryption\n Enter your choice: ")

#Encrytion
if toDoChoice == '1':
	plaintext = input("Enter plaintext of 128 bits(16 byte string): ")
	while ( len(plaintext) != 16 ):
		print("Entered plaintext consists of ",len(plaintext)," bytes")
		plaintext = input("Given input is not of 16 bytes\nEnter plaintext of 128 bits(16 byte string): ")
	keyList=keyInput()
	print("\nplaintext entered:\n\t"+ plaintext)
	plaintextMatrix=textToMatrix(plaintext)
	print("key entered:")
	print("\t",keyList)
	originalKeyMatrix=hexToMatrix(keyList)
	print("\nAES encryption started")
	
	#round 0
	print("\nPlaintext matrix:")
	printMatrix(plaintextMatrix)
	print("key matrix:")
	printMatrix(originalKeyMatrix)
	expandKey(originalKeyMatrix)
	currentroundKey=roundKey(0)
	print("key used for round 0:")
	printMatrix(currentroundKey)
	currentCiphertext=xorMatrix(plaintextMatrix,currentroundKey)
	print("cipher text after round 0:") 
	printMatrix(currentCiphertext)
	
	#rounds 1 to 9 
	for i in range(1,10):
		currentroundKey=roundKey(i)
		print("key used for round ",i,":")
		printMatrix(currentroundKey)
		substitutedMatrix=forwardSubstitution(currentCiphertext)
		shiftedMatrix=forwardShiftRow(substitutedMatrix)
		coloumnMixedMatrix=forwardMixColoumn(shiftedMatrix)
		currentCiphertext=xorMatrix(coloumnMixedMatrix,currentroundKey)
		print("cipher text after round ",i,":")
		printMatrix(currentCiphertext)

	#round 10
	currentroundKey=roundKey(10)
	print("key used for round 10:")
	printMatrix(currentroundKey)
	substitutedMatrix=forwardSubstitution(currentCiphertext)
	shiftedMatrix=forwardShiftRow(substitutedMatrix)
	currentCiphertext=xorMatrix(shiftedMatrix,currentroundKey)
	print("cipher text after round 10:") 
	printMatrix(currentCiphertext)
	print("\nAES encryption process terminated successfully")
	ciphertext = []		#matrix to list coversion of ciphertext
	for i in range(4):
		for j in range(4):
			ciphertext.append(currentCiphertext[j][i])
	#printing summary
	print('\nEncryption Summary')
	print('-'*50,"\n")
	print('Plain text : ', plaintext)
	print('-'*50)
	print('Key (Hex) : ',hexListToString(keyList))
	print('-'*50)
	print('Cipher text (Hex) : ', hexListToString(ciphertext))
	print('-'*50)
	ct = ''		#hexadecimal list to normal string of characters
	for i in ciphertext:
		ct += chr(i)
	print('Cipher text : ', ct)
	print('-'*50)

#Decryption
elif toDoChoice == '2':
	ciphertext = cipherTextInput()
#	while ( len(ciphertext) != 16 ):
#		print("Entered plaintext consists of ",len(ciphertext)," bytes")
#		ciphertext = input("Given input is not of 16 bytes\nEnter ciphertext of 128 bits(16 byte string): ")
	keyList=keyInput()
	#print("\nciphertext entered:\n\t"+ ciphertext)
	ciphertextMatrix=hexToMatrix(ciphertext)
	print("key entered:")
	print("\t",keyList)
	originalKeyMatrix=hexToMatrix(keyList)
	print("\nAES Decryption started")
	print("\nciphertext matrix:")
	printMatrix(ciphertextMatrix)
	print("key matrix:")
	printMatrix(originalKeyMatrix)
	expandKey(originalKeyMatrix)
	currentroundKey=decryptionRoundKey(0)
	print("key used for round 0:")
	xoredMatrix=xorMatrix(ciphertextMatrix,currentroundKey)
	shiftedMatrix=backwardShiftRow(xoredMatrix)
	currentCiphertext=backwardSubstitution(shiftedMatrix)
	printMatrix(currentroundKey)
	print("cipher text after round 0:") 
	printMatrix(currentCiphertext)
	for i in range(1,10):
		currentroundKey=decryptionRoundKey(i)
		print("key used for round ",i,":")
		printMatrix(currentroundKey)
		xoredMatrix=xorMatrix(currentCiphertext,currentroundKey)
		currentCiphertext=backwardMixColoumn(xoredMatrix)
		shiftedMatrix=backwardShiftRow(currentCiphertext)
		currentCiphertext=backwardSubstitution(shiftedMatrix)
		print("cipher text after round ",i,":")
		printMatrix(currentCiphertext)
	currentroundKey=decryptionRoundKey(10)
	print("key used for round 10:")
	printMatrix(currentroundKey)
	currentCiphertext=xorMatrix(currentCiphertext,currentroundKey)
	print("plain text matrix after round 10:") 
	printMatrix(currentCiphertext)
	print("\nAES decryption process terminated successfully")
	out = []	#matrix to list coversion of plaintext
	for i in range(4):
		for j in range(4):
			out.append(currentCiphertext[j][i])
	#printing summary
	print('\nDecryption Summary')
	print('-'*50)
	print('\nCipher text : ', ciphertext)
	print('-'*50)
	print('Key (Hex) : ',hexListToString(keyList))
	print('-'*50)
	pt = ''	#hexadecimal list to normal string of characters
	for i in out:
		pt += chr(i)
	print('Plain Text (Hex) : ', hexListToString(out))
	print('-'*50)
	print('Plain text : ', pt)

else :
	print("Wrong choice\nexecution terminated\nPlease re-execute file with correct choice")
	
#end
