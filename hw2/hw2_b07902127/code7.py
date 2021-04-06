from pwn import *
from Cryptodome.Cipher import Salsa20
from Cryptodome.Hash import SHA256, HMAC
from binascii import hexlify, unhexlify
from datetime import datetime
import os
import string
import random


def decrypt(key, msg):
	msg = unhexlify(msg.encode())
	nonce = msg[:8]
	c = msg[8:]
	cipher = Salsa20.new(key=key, nonce=nonce)
	return cipher.decrypt(c)

def mac(key, msg):
	h = HMAC.new(key, digestmod=SHA256)
	h.update(msg)
	return h.hexdigest()

myname = "eya301ye6"
r_alc = remote('cns.csie.org', 10221)
r_alc.recvuntil('>')
r_alc.send("1\n")
received = r_alc.recvline().decode("utf-8")
#print(received)
nonce_alice = received.split('||')[0][1:]

print("Na is:", nonce_alice)

r_kdc = remote('cns.csie.org', 10220)
r_kdc.recvuntil('>')
r_kdc.send("1\n") # Register
r_kdc.send(myname + "\n") # name

msg = r_kdc.recvline().decode("utf-8")
#print("msg:", msg)
my_KE = msg.split(',')[0][9:-1]
my_KM = msg.split(',')[1][2:-3]
print("my_KE:", my_KE)
print("my_KM:", my_KM)

print("")

r_kdc = remote('cns.csie.org', 10220)
r_kdc.recvuntil('>')
r_kdc.send("2\n")
r_kdc.recv()
r_kdc.recv()
r_kdc.send(nonce_alice+"||0||Alice||"+myname+"\n")
msg = r_kdc.recv().decode("utf-8")
#print(msg)
share_c1 = msg.split(',')[0][2:-1]
share_c2 = msg.split(',')[2][2:-1]
print("share_c1:", share_c1)
print("share_c2:", share_c2)

print("")

r_kdc = remote('cns.csie.org', 10220)
r_kdc.recvuntil('>')
r_kdc.send("2\n")
r_kdc.recv()
r_kdc.recv()
r_kdc.send(nonce_alice+"||0||Alice||Bob\n")
msg = r_kdc.recv().decode("utf-8")
#print(msg)
t1 = msg.split(',')[1][2:-1]
print("t1:", t1, "\n")

to_send = share_c1+"||"+t1+"||"+"Bob||0\n"
r_alc.send(to_send)
r_alc.recv()
msg = r_alc.recv().decode("utf-8")[1:-1]
print("encrypted message:", msg, "\n")

skey = decrypt(unhexlify(my_KE.encode()), share_c2)

flag1 = decrypt(unhexlify(skey), msg)
print("flag1:", str(flag1)[2:-1])

pause()

r_alc.close()
r_kdc.close()


def attempt(name):
	try:
		r_admin = remote('cns.csie.org', 10220)
	except:
		print("Failed to connect to cns.csie.org:10220")
		return False, "Failed", "Failed"
	r_admin.recvuntil('> ')
	r_admin.send('1\n')
	r_admin.recvuntil(': ')
	r_admin.send(name+"\n")
	msg = r_admin.recvline().decode()
	if msg.find('Nope') != -1 or msg.find('User exists') != -1:
		r_admin.close()
		return False, "Failed", "Failed"
	print(msg)
	ke = msg.split(',')[0][2:-1]
	km = msg.split(',')[1][2:-3]
	return True, ke, km

def run():
	name = "Admin" # + random.choice(string.ascii_lowercase)
	f, ke, km = attempt(name)
	#print(f, ke, km)
	if f == True:
		r = remote('cns.csie.org', 10220)
		r.recvuntil('> ')
		r.send("3\n")
		r.recvuntil(': ')
		r.sendline(name)
		nonce = r.recvline().decode()
		#print(nonce)
		admin_nonce = nonce[7:-1]
		#print(admin_nonce)
		r.recvuntil('Ticket: ')
		data = name+"||"+admin_nonce
		s = mac(unhexlify(km.encode()), data.encode())
		r.sendline(s)
		msg = r.recvline().decode()[:-1]
		#print(msg)
		ss = decrypt(unhexlify(ke.encode()), msg)
		print("msg:", ss)
		f = open('flag2_result', 'a')
		f.write(str(ss)[2:-1])
		f.close()
		r.close()
		
'''
while True:
	try:
		run()
	except:
		print("ERRRRRRRRORRRRRRRRRR!")
'''
while True:
	run()
