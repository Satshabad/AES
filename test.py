__author__ = 'satshabad'

import unittest
import AES

class GeneticTest(unittest.TestCase):
    def setUp(self):
        self.aes = AES.AES(3)

    def test__subBytes(self):
        given = [[0x00, 0x10, 0x20, 0x30],
                 [0x40, 0x50, 0x60, 0x70],
                 [0x80, 0x90, 0xa0, 0xb0],
                 [0xc0, 0xd0, 0xe0,0xf0]]

        expected = [[0x63, 0xca, 0xb7, 0x04],
                    [0x09, 0x53, 0xd0 ,0x51],
                    [0xcd ,0x60, 0xe0, 0xe7],
                    [0xba, 0x70, 0xe1, 0x8c]]

        self.assertEqual(self.aes._subBytes(given), expected)
        self.assertEqual(self.aes._subBytes(self.aes._invSubBytes(given)), given)

    def test__invSubBytes(self):
        expected = [[0x00, 0x10, 0x20, 0x30],
            [0x40, 0x50, 0x60, 0x70],
            [0x80, 0x90, 0xa0, 0xb0],
            [0xc0, 0xd0, 0xe0,0xf0]]

        given = [[0x63, 0xca, 0xb7, 0x04],
            [0x09, 0x53, 0xd0 ,0x51],
            [0xcd ,0x60, 0xe0, 0xe7],
            [0xba, 0x70, 0xe1, 0x8c]]

        self.assertEqual(self.aes._invSubBytes(given), expected)
        self.assertEqual(self.aes._invSubBytes(self.aes._subBytes(given)), given)


    def test__shiftRows(self):
        expected = [[0x63, 0x9, 0xcd, 0xba],
                    [0x53, 0x60, 0x70 ,0xca],
                    [0xe0, 0xe1, 0xb7, 0xd0],
                    [0x8c, 0x4, 0x51, 0xe7]]

        given = [[0x63,0x09, 0xcd, 0xba],
                [0xca, 0x53, 0x60 ,0x70],
                [0xb7 ,0xd0, 0xe0, 0xe1],
                [0x04, 0x51,  0xe7, 0x8c]]

        self.assertEqual(self.aes._shiftRows(given), expected)
        self.assertEqual(self.aes._shiftRows(self.aes._invShiftRows(given)), given)



    def test__invShiftRows(self):
        given = [[0x63, 0x9, 0xcd, 0xba],
            [0x53, 0x60, 0x70 ,0xca],
            [0xe0, 0xe1, 0xb7, 0xd0],
            [0x8c, 0x4, 0x51, 0xe7]]

        expected = [[0x63,0x09, 0xcd, 0xba],
            [0xca, 0x53, 0x60 ,0x70],
            [0xb7 ,0xd0, 0xe0, 0xe1],
            [0x04, 0x51,  0xe7, 0x8c]]

        self.assertEqual(self.aes._invShiftRows(given), expected)
        self.assertEqual(self.aes._invShiftRows(self.aes._shiftRows(given)), given)


    def test__mult(self):
        self.aes._mult(0b00010111, 0b10110101)

    def test__invMixColumns(self):

        #6353e08c 0960e104 cd70b751 bacad0e7
        expected = [[0x63, 0x9, 0xcd, 0xba],
                    [0x53, 0x60, 0x70 ,0xca],
                    [0xe0, 0xe1, 0xb7, 0xd0],
                    [0x8c, 0x4, 0x51, 0xe7]]



        # 5f726415 57f5bc92 f7be3b29 1db9f91a
        given = [[0x5f, 0x57, 0xf7, 0x1d],
                [0x72, 0xf5, 0xbe, 0xb9],
                [0x64, 0xbc, 0x3b, 0xf9],
                [0x15, 0x92, 0x29, 0x1a]]


        self.print_in_col_order(self.aes._invMixColumns(expected))




    def test__mixColumns(self):

        #6353e08c 0960e104 cd70b751 bacad0e7
        given = [[0x63, 0x9, 0xcd, 0xba],
                [0x53, 0x60, 0x70 ,0xca],
                [0xe0, 0xe1, 0xb7, 0xd0],
                [0x8c, 0x4, 0x51, 0xe7]]



        # 5f726415 57f5bc92 f7be3b29 1db9f91a
        expected = [[0x5f, 0x57, 0xf7, 0x1d],
                    [0x72, 0xf5, 0xbe, 0xb9],
                    [0x64, 0xbc, 0x3b, 0xf9],
                    [0x15, 0x92, 0x29, 0x1a]]

        self.assertEqual(self.aes._mixColumns(given), expected)
        #self.assertEqual(self.aes._mixColumns(self.aes._invMixColumns(given)), given)


    def test__rot(self):
        self.assertEqual(self.aes._rot([0x63, 0x9, 0xcd, 0xba]), [ 0x9, 0xcd, 0xba, 0x63])

    def text__subWord(self):
        self.assertEqual(self.aes._rot([0x63, 0x9, 0xcd, 0xba]), [0x05, 0x60, 0x86, 0x62])

    def test__xtime(self):
        self.assertEqual(self.aes._xtime(0b01010110), 0b10101100)
        self.assertEqual(self.aes._xtime(0b10101100), 0b001000011)


    def print_in_col_order(self, s):
        for colNum in range(len(s[0])):
            for row in s:
                print hex(row[colNum]),
            print

    def hex_to_matrix(self, string):
        s = [[0 for val in row] for row in range(4)]
        dexOfString = 0
        for i, row in enumerate(s):
            for j, val in enumerate(row):
                s[j][i] = hex(string[dexOfString: dexOfString+2])
        return s



if __name__ == '__main__':
    unittest.main()



