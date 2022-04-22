#page 75
import pandas as pd
from hashlib import sha256
import struct
import time
import binascii

#page 76
#open data file
with open("transactions.txt",encoding="utf-8") as f:
	tx=f.readlines()

tx_list=[]

# this is for the bitcoin mining data format
for t in tx:
	t=t.replace("\n","")
	tx_list.append(t.split(", "))

# Does pandas display work in console?
#tx_data = pd.DataFrame(tx_list, columns=["id","content","tx_fee"])


# page 77 has some code about manual input to select some data?
# skipping for now???

#page 84


# double hashing
def dsha(tx):
	return sha256(sha256(tx).digest()).digest()

# reverse buffer
def rev(buf):
	return buf[::-1]

# page 85 has 4 transactions in hex
# I hope the OCR doesn't fail me
tx_A = bytes.fromhex('0000000003ce00000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a010000004341041b0e8c2567c12536aa13357b79a073dc4444acb83c4ec7a0e2f99dd7457516c5817242da796924ca4e99947d087fedf9ce467cb9f7c6287078f801df276fdf84ac00000000')

tx_B = bytes.fromhex('0000000001032e38e9c0a84c6046d687d10556dcacc41d275ec55fc00779ac8\
8fdf357a187000000008c493046022100c352d3dd993a981beba4a63ad15c209275ca9470abfcd\
57da93b58e4eb5dce82022100840792bc1f456062819f15d33ee7055cf7b5ee1af1ebcc6028d9c\
db1c3af7748014104f46db5e9d61a9dc27b8d64ad23e7383a4e6ca164593c2527c038c0857eb67\
ee8e825dca65046b82c9331586c82e0fd1f633f25f87c161bc6f8a630121df2b3d3ffffffff020\
0e32321000000001976a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac000fe208010\
000001976a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac00000000')
tx_C = bytes.fromhex('0f00000001c33ebff2a709f13d9f9a7569ab16a32786af7d7e2de09265e41c6\
1d078294ecf010000008a4730440220032d30df5ee6f57fa46cddb5eb8d0d9fe8de6b342d27942\
ae90a3231e0ba333e02203deee8060fdc70230a7f5b4ad7d7bc3e628cbe219a886b84269eaeb81\
e26b4fe014104ae31c31bf91278d99b8377a35bbce5b27d9fff15456839e919453fc7b3f721f0b\
a403ff96c9deeb680e5fd341c0fc3a7b90da4631ee39560639db462e9cb850fffffffff0240420\
f00000000001976a914b0dcbf97eabf4404e31d952477ce822dadbe7e1088acc060d2110000000\
01976a9146b1281eec25ab4e1e0793ff4e08ab1abb3409cd988ac00000000')
tx_D = bytes.fromhex('0c400000670b6072b386d4a773235237f64c1126ac3b240c84b917a3909ba1c43ded5f51f4000000008c493046022100bb1ad26df930a51cce110cf44f7a48c3c561fd977500b1ae5d6b6fd13d0b3f4a022100c5b42951acedff14abba2736fd574bdb465f3e6f8da12e2c5303954aca7f78f3014104a7135bfe824c97ecc01ec7d7e336185c81e2aa2c41ab175407c09484ce9694b44953fcb751206564a9c24dd094d42fdbfdd5aad3e063ce6af4cfaaea4ea14fbbffffffff0140420f00000000001976a91439aa3d569e06a1d7926dc4be1193c99bf2eb9ee088ac00000000')



# page 86 hashes the transactions

ha=dsha(tx_A)
hb=dsha(tx_B)
hc=dsha(tx_C)
hd=dsha(tx_D)
print(ha.hex())
print(hb.hex())
print(hc.hex())
print(hd.hex())
# yes that works, with pain

#also these

hab=dsha(ha+hb)
hcd=dsha(hc+hd)

print("")
print(hab.hex())
print(hcd.hex())

habcd=dsha(hab+hcd)

print(habcd.hex())
merkle_root=rev(habcd)
print(rev(habcd).hex())



# page 89
# seems like it's dealing with some block info

ver=2
prev_block="000000000000000117c80378b8da0e33559b5997f2ad55e2f7d18ec1975b9717"
time_=0x5d21a868


# page 93
# this deals with target
# an 8-digit hex number defines a "target" number (using a formula)
# and you have to make the block hash <= this target

bits="0x1709f8d9"
exponent=bits[2:4]
coefficient=bits[4:]
exponent2=int("8",16) * (int(exponent,16)-int("3",16))
# isn't this just "8 * int(blah) - 3"? why "int("8",16)"??

target= int(coefficient, 16) * (int("2",16))**exponent2

print("")
print(target)

target1=format(target,"x")

print(str(target1).zfill(64)) 


# page 95
# speaking of, what the hell is struct.pack

target_byte=bytes.fromhex(str(target1).zfill(64))
partial_header=struct.pack("<L", ver)+bytes.fromhex(prev_block)[::-1]+merkle_root[::-1]+struct.pack("<LL", time_, int(bits, 16))

# page 96
# it asks a user input to be nonce, I'm just doing set value
nonce=0

# page 97
# a while loop to mine


mining_start_time=time.time()
while nonce<2**32:
	header=partial_header+struct.pack("<L", nonce)
	hash=dsha(header)
	
	if nonce%50000==49999:
		mining_time=time.time()-mining_start_time
		hash_rate=(nonce+1)/mining_time
		print("Calculated {} nonces at {}/sec".format(nonce, hash_rate))
	
	if hash[::-1]<target_byte:
		print("Cracked at nonce {} with hash {}".format(nonce, binascii.hexlify(hash[::-1])))
		break
	
	nonce+=1

