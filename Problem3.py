if __name__ == '__main__':
    import AES
    import sys


    key = list(sys.stdin.read(24))
    key = [ord(ch) for ch in key]
    a = AES.AES(key)

    listOfBytes = []
    block = [ord(byte) for byte in list(sys.stdin.read(16))]
    while block:
        listOfBytes += a.decrypt(block)
        block = [ord(byte) for byte in list(sys.stdin.read(16))]

    st = ''
    for byte in listOfBytes:
        st += chr(byte)

    sys.stdout.write(st)
