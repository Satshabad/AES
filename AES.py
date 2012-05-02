import collections
import copy

class AES:
    def __init__(self, z):
        pass
        # The index of the current state in this AES cipher.
        # int current

        # The inverse S-Box substitution table.
        self.invSBox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
                        0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
                        0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
                        0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
                        0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
                        0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
                        0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
                        0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
                        0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
                        0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
                        0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
                        0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
                        0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
                        0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
                        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
                        0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
                        0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
                        0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
                        0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
                        0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
                        0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
                        0x21, 0x0c, 0x7d]

        # The number of 32-bit words comprising the plaintext and columns
        # comprising the state matrix of an AES cipher.
        self.Nb = 4

        # The number of 32-bit words comprising the cipher key in this AES cipher.
        Nk = 0
        if len(z) == 16:
            Nk = 4
        elif len(z) == 24:
            Nk = 6
        elif len(z) == 32:
            Nk = 8
        else:
            raise ValueError


        # The number of rounds in this AES cipher.
        self.Nr = Nk + self.Nb + 2

        # The state matrices in this AES cipher.
        # int[][][] s

        # The S-Box substitution table.
        self.sBox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
                     0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
                     0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
                     0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
                     0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
                     0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
                     0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
                     0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
                     0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
                     0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
                     0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
                     0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
                     0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
                     0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
                     0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
                     0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
                     0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
                     0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
                     0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
                     0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
                     0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
                     0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
                     0x54, 0xbb, 0x16]


        self.Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
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
                    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d]

        # The key schedule in this AES cipher.
        self.expandedKey = self._expandKey(z, Nk)

    def encrypt(self, x): # returns array of bytes
        """
        Encrypts a 128-bit (16-byte) plaintext block using this AES cipher.

        Specified by:
        encrypt in interface AbstractAES

        Parameters:
        x - A 128-bit (16-byte) plaintext block to be encrypted.

        Returns:
        The 128-bit (16-byte) ciphertext block produced by encryption.

        Throws:
        IllegalArgumentException - if the plaintext block length is not 128 bits (i.e. 16 bytes).
        """

        if not len(x) == 16:
            raise ValueError


        state = [[0 for val in range(self.Nb)] for row in range(self.Nb)]

        byteIndex = 0
        for i, row in enumerate(state):
            for j, val in enumerate(row):
                state[j][i] = x[byteIndex]
                byteIndex +=1


        state = self._addRoundKey(state, self.expandedKey[0:self.Nb])




        for round in range(1, self.Nr):

            state = self._subBytes(state)
            state = self._shiftRows(state)
            state = self._mixColumns(state)
            state = self._addRoundKey(state, self.expandedKey[round*self.Nb:((round+1)*self.Nb-1)+1])

        state = self._subBytes(state)
        state = self._shiftRows(state)
        state = self._addRoundKey(state, self.expandedKey[self.Nr*self.Nb:(self.Nr+1)*self.Nb])

        cipherText = []

        for i in range(len(state)):
            for j in range(len(state[0])):
                cipherText.append(state[j][i])

        return cipherText



    def decrypt(self, y): # returns array of bytes
        """
       Decrypts a 128-bit (16-byte) ciphertext block using this AES cipher.

        Specified by:
        decrypt in interface AbstractAES

        Parameters:
        y - A 128-bit (16-byte) ciphertext block to be decrypted.

        Returns:
        The 128-bit (16-byte) plaintext block produced by decryption.

        Throws:
        IllegalArgumentException - if the ciphertext block length is not 128 bits (i.e. 16 bytes).
        """
        if not len(y) == 16:
            raise ValueError


        state = [[0 for val in range(self.Nb)] for row in range(self.Nb)]

        byteIndex = 0
        for i, row in enumerate(state):
            for j, val in enumerate(row):
                state[j][i] = y[byteIndex]
                byteIndex +=1

        state = self._addRoundKey(state, self.expandedKey[self.Nr*self.Nb : ((self.Nr+1)*self.Nb-1)+1])

        for round in range(self.Nr-1,0, -1):


            state = self._invShiftRows(state)
            state = self._invSubBytes(state)
            state = self._addRoundKey(state, self.expandedKey[round*self.Nb:((round+1)*self.Nb-1)+1])
            state = self._invMixColumns(state)

        state = self._invShiftRows(state)
        state = self._invSubBytes(state)
        state = self._addRoundKey(state, self.expandedKey[0:self.Nb])

        cipherText = []

        for i in range(len(state)):
            for j in range(len(state[0])):
                cipherText.append(int(state[j][i]))

        return cipherText

    def _expandKey(self, key, Nk):

        returnWords = [[] for val in range(self.Nb*(self.Nr+1))]
        temp = []
        i = 0
        while i < Nk:
            returnWords[i] = [key[4*i], key[(4*i)+1], key[(4*i)+2], key[(4*i)+3]]
            i +=1

        i = Nk
        while i < self.Nb * (self.Nr+1):
            temp = returnWords[i-1][:]
            if i % Nk == 0:


                temp = self._subWord(self._rot(temp))
                x = temp[:]
                x[0] = x[0] ^ self.Rcon[i/Nk]
                temp[0] = temp[0] ^ self.Rcon[i/Nk]

            elif Nk > 6 and i % Nk == 4:
                temp = self._subWord(temp)
            returnWords[i] = self._xorListsOfBytes(returnWords[i-Nk], temp)
            i += 1
        return returnWords

    def _xorListsOfBytes(self, byteList1, byteList2):
        return [byteList1[i] ^ byteList2[i] for i in range(len(byteList2))]

    def _addRoundKey(self, state, round): # returns state matrix
        """
        Adds the key schedule for a round to a state matrix.

        Parameters:
        s - A state matrix having Nb columns and 4 rows.
        round - A round of the key schedule w to be added.

        Returns:
        s, after adding the key schedule for round.
        """
        newState = [[0 for val in row] for row in state]

        for i, row in enumerate(state):
            for j, val in enumerate(row):
                newState[j][i] = state[j][i] ^ round[i][j]

        return newState


    def _invMixColumns(self, state): # returns state matrix
        """
        Unmixes each column of a state matrix. Multiplies each column--a polynomial in GF(GF(28)4)--times {0b}x3+{0d}2+{09}x+{0e} modulo x4+1.

        Parameters:
        s - A state matrix having Nb columns and 4 rows.

        Returns:
        s, after unmixing each column.
        """
        state = copy.deepcopy(state)

        invColBox = [[14, 11 ,13, 9],
                     [9, 14, 11, 13],
                     [13, 9, 14, 11],
                     [11, 13, 9, 14]]

        colOrderState = [[0 for val in row] for row in state ]

        for i in range(len(state)):
            for j in range(len(state[0])):
                colOrderState[j][i] = state[i][j]


        newState = [[0 for val in row] for row in state ]

        def matrixMult(matrix1, array):

            returnArray = [0 for val in array]
            for i, row in enumerate(matrix1):
                for j, boxVal in enumerate(row):

                    returnArray[i] = self._mult(boxVal, array[j]) ^ returnArray[i]
            return returnArray


        for i, row in enumerate(colOrderState):
            newState[i] = matrixMult(invColBox, row)




        for i in range(len(state)):
            for j in range(len(state[0])):
                state[i][j] = newState[j][i]


        return state

    def _invShiftRows(self, state): # returns state matrix
        """
        Applies an inverse cyclic shift to the last 3 rows of a state matrix.

        Parameters:
        s - A state matrix having Nb columns and 4 rows.

        Returns:
        s, after an inverse cyclic shift is applied to each row.
        """
        for rowNumber, row in enumerate(state):
            rowForRotate = collections.deque(row)
            rowForRotate.rotate(rowNumber)
            state[rowNumber] = list(rowForRotate)

        return state

    def _invSubBytes(self, state): # returns state matrix
        """
        Applies inverse S-Box substitution to each byte of a state matrix.

        Parameters:
        s - A state matrix having Nb columns and 4 rows.

        Returns:
        s, after inverse S-box substitution is applied to each byte.
        """
        for i, row in enumerate(state):
            for j, value in enumerate(row):
                state[i][j] = self.invSBox[value]

        return state

    def _mixColumns(self, state): # returns state matrix
        """
        Mixes each column of a state matrix. Multiplies each column--a polynomial in GF(GF(28)4)--times {03}x3+{01}x2+{01}x+{02} modulo x4+1.

        Parameters:
        s - A state matrix having Nb columns and 4 rows.

        Returns:
        s, after mixing each column.
        """
        state = copy.deepcopy(state)

        colBox = [[2,3,1,1],
                  [1,2,3,1],
                  [1,1,2,3],
                  [3,1,1,2]]

        rowMajorState = [[0 for val in row] for row in state ]

        for i in range(len(state)):
            for j in range(len(state[0])):
                rowMajorState[j][i] = state[i][j]

        newRowMajorState = [[0 for val in row] for row in state ]

        def matrixMult(matrix1, array):
            returnArray = [0 for val in array]
            for i, row in enumerate(matrix1):
                for j, boxVal in enumerate(row):
                    returnArray[i] = self._mult(boxVal, array[j]) ^ returnArray[i]

            return returnArray


        for i, row in enumerate(rowMajorState):
            newRowMajorState[i] = matrixMult(colBox, row)


        for i in range(len(state)):
            for j in range(len(state[0])):
                state[i][j] = newRowMajorState[j][i]

        return state



    def _mult(self, byte1, byte2): # returns a(x)b(x) (a byte)
        """
        Multiplies two polynomials a(x), b(x) in GF(28) modulo the irreducible polynomial m(x) = x8+x4+x3+x+1. (i.e. m(x) = 0x11b).

        Parameters:
        a - A polynomial a(x) = a7x7+a6x6+a5x5+a4x4+a3x3+a2x2+a1x+a0 in GF(28).
        b - A polynomial b(x) = b7x7+b6x6+b5x5+b4x4+b3x3+b2x2+b1x+b0 in GF(28).

        Returns:
        a(x)b(x) modulo x8+x4+x3+x+1.
        """

        sum = 0b00000000
        toBeXored = byte2
        for i in range(8):
            if (byte1 & 0b00000001) == 0b00000001:
                sum = sum ^ toBeXored

            toBeXored = self._xtime(toBeXored)
            byte1 = byte1 >> 1

        return sum


    def _rot(self, word): # returns a 4 byte word
        """
        Applies a cyclic permutation to a 4-byte word.

        Parameters:
        w - A 4-byte word.

        Returns:
        w, after cyclic permutation is applied.
        """
        wordForRotate = collections.deque(word)
        wordForRotate.rotate(-1)
        return list(wordForRotate)


    def _shiftRows(self, state): # returns state matrix
        """
        Applies a cyclic shift to the last 3 rows of a state matrix.

        Parameters:
        s - A state matrix having Nb columns and 4 rows.

        Returns:
        s, after a cyclic shift is applied to each row.
        """
        for rowNumber, row in enumerate(state):
            rowForRotate = collections.deque(row)
            rowForRotate.rotate(-rowNumber)
            state[rowNumber] = list(rowForRotate)

        return state

    def _subBytes(self, state):  # returns state matrix
        """
        Applies S-Box substitution to each byte of a state matrix.

        Parameters:
        s - A state matrix having Nb columns and 4 rows.

        Returns:
        s, after S-box substitution is applied to each byte.
        """

        for i, row in enumerate(state):
            for j, value in enumerate(row):
                state[i][j] = self.sBox[value]

        return state


    def _subWord(self, word): # returns a 4 byte word
        """
        Applies S-box substitution to each byte of a 4-byte word.

        Parameters:
        w - A 4-byte word.

        Returns:
        w, after S-box substitution is applied to each byte.
        """
        for i, byte in enumerate(word):
            word[i] = self.sBox[byte]
        return word

    def _xtime(self, byte): # returns a byte
        """
        Multiplies x times a polynomial b(x) in GF(28) modulo the irreducible polynomial m(x) = x8+x4+x3+x+1. (i.e. m(x) = 0x11b).

        Parameters:
        b - A polynomial b(x) = b7x7+b6x6+b5x5+b4x4+b3x3+b2x2+b1x+b0 in GF(28).

        Returns:
        xb(x) mod x8+x4+x3+x+1.
        """

        shiftedB = byte << 1
        if (shiftedB & 0b100000000) == 0b100000000:
            shiftedB = shiftedB ^ 0b100011011;

        return shiftedB;

