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
        self.assertEqual(self.aes._mult(0b00010111, 0b10110101), 0b11000100)

    def test__invMixColumns(self):


        # bd6e7c3df2b5779e0b61216e8b10b689
        given = [[189, 242, 11, 139], [110, 181, 97, 16], [124, 119, 33, 182], [61, 158, 110, 137]]

        # 4773b91ff72f354361cb018ea1e6cf2c
        expected = [[71, 247, 97, 161], [115, 47, 203, 230], [185, 53, 1, 207], [31, 67, 142, 44]]

        self.hex_to_matrix('5f72641557f5bc92f7be3b291db9f91a')
        #print self.aes._invMixColumns(expected)



    def test__mixColumns(self):
        #6353e08c0960e10cd70b751bacad0e7
        given = [[99, 9, 215, 172], [83, 96, 11, 173], [224, 225, 117, 14], [140, 12, 27, 7]]


        #5f72641557f5bc92f7be3b291db9f91a
        expected = [[95, 87, 247, 29], [114, 245, 190, 185], [100, 188, 59, 249], [21, 146, 41, 26]]

        print 'mix(given)', self.aes._mixColumns(given)

        self.assertEqual(self.aes._mixColumns(given), expected)
        #self.assertEqual(self.aes._mixColumns(self.aes._invMixColumns(given)), given)


    def test__xtime(self):
        self.assertEqual(self.aes._xtime(0b01010110), 0b10101100)
        self.assertEqual(self.aes._xtime(0b10101100), 0b001000011)


    def print_in_col_order(self, s):
        for colNum in range(len(s[0])):
            for row in s:
                print hex(row[colNum]),
            print

    def hex_to_matrix(self, string):
        s = [[0 for val in range(4)] for row in range(4)]
        dexOfString = 0
        for i, row in enumerate(s):
            for j, val in enumerate(row):
                s[j][i] = int(string[dexOfString: dexOfString+2], 16)
                dexOfString += 2
        print s


if __name__ == '__main__':
    unittest.main()



