
from Crypto.Cipher import AES

 

kek = b'\x10\x2b\xcb\xe5\x4d\xd7\xb2\x33\x94\x6a\xd9\xb0\xa8\x54\x27\xaf\xd5\x16\xf1\x8e\x6e\xa4\xf7\x4b\xb8\x35\x1c\x37\x26\x48\xc7\xfe'
       


iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B'

type = AES.MODE_GCM

encryptInstance = AES.new(kek, AES.MODE_GCM, nonce=iv, mac_len=16)

#encryptedKey, tag = encryptInstance.encrypt_and_digest(b'\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08')

#encryptedKey, tag = #encryptInstance.encrypt_and_digest(b'\x5d\xc4\x91\xfa\x8b\xd7\xbe\x62\xaa\x83\xa4\x2e\xf1\x1d\x80\xd8\x47\x2c\x5d\xe1\xbb\x76\x72\xef\x5d\x54\x10\xb2\x17\xd5\x8f\x78')

encryptedKey, tag = encryptInstance.encrypt_and_digest(b'\x59\xb2\x30\xa0\x94\xee\xc2\x38\x49\xd5\x53\xce\xe6\xbe\xc5\x0f\x3a\x82\xd2\xa2\x1d\x9f\xf4\x7a\x6b\x43\x51\xe1\xdd\x38\x35\x8c')

print("CT Length: " + str(len(encryptedKey)))

print(hex(encryptedKey[0]) + ", "
	+ hex(encryptedKey[1]) + ", "
	+ hex(encryptedKey[2]) + ", "
	+ hex(encryptedKey[3]) + ", "
	+ hex(encryptedKey[4]) + ", "
	+ hex(encryptedKey[5]) + ", "
	+ hex(encryptedKey[6]) + ", "
	+ hex(encryptedKey[7]) + ", "
	)

print(hex(encryptedKey[8]) + ", "
	+ hex(encryptedKey[9]) + ", "
	+ hex(encryptedKey[10]) + ", "
	+ hex(encryptedKey[11]) + ", "
	+ hex(encryptedKey[12]) + ", "
	+ hex(encryptedKey[13]) + ", "
	+ hex(encryptedKey[14]) + ", "
	+ hex(encryptedKey[15]) + ", "
	)

print(hex(encryptedKey[16]) + ", "
	+ hex(encryptedKey[17]) + ", "
	+ hex(encryptedKey[18]) + ", "
	+ hex(encryptedKey[19]) + ", "
	+ hex(encryptedKey[20]) + ", "
	+ hex(encryptedKey[21]) + ", "
	+ hex(encryptedKey[22]) + ", "
	+ hex(encryptedKey[23]) + ", "
	)

print(hex(encryptedKey[24]) + ", "
	+ hex(encryptedKey[25]) + ", "
	+ hex(encryptedKey[26]) + ", "
	+ hex(encryptedKey[27]) + ", "
	+ hex(encryptedKey[28]) + ", "
	+ hex(encryptedKey[29]) + ", "
	+ hex(encryptedKey[30]) + ", "
	+ hex(encryptedKey[31]) + ", "
	)

print("Tag Length: " + str(len(tag)))
print(hex(tag[0]) + ", "
	+ hex(tag[1]) + ", "
	+ hex(tag[2]) + ", "
	+ hex(tag[3]) + ", "
	+ hex(tag[4]) + ", "
	+ hex(tag[5]) + ", "
	+ hex(tag[6]) + ", "
	+ hex(tag[7]) + ", "
	)

print(hex(tag[8]) + ", "
	+ hex(tag[9]) + ", "
	+ hex(tag[10]) + ", "
	+ hex(tag[11]) + ", "
	+ hex(tag[12]) + ", "
	+ hex(tag[13]) + ", "
	+ hex(tag[14]) + ", "
	+ hex(tag[15]) + ", "
	)




