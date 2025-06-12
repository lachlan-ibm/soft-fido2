

import cbor2 as cbor


class CaBLE(object):

    def __init__(self):
        return


    def decode_qr_data(self, data):
        chunkSize = 17
        chunkBytes = 7
        buff = b''
        for i in range( int(len(data)/chunkSize) ):
            buff += (int(data[i * chunkSize: (i + 1) * chunkSize])).to_bytes(chunkBytes, 'little')
        if len(data) % chunkSize != 0:
            #unpack the trailing bytes
            buff += (int(data[int(len(data)/chunkSize):])).to_bytes(chunkBytes, 'little')
        return cbor.loads(buff)
