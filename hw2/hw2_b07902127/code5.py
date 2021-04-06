from pwn import *
from threading import Thread

def f1():
	r = remote('cns.csie.org', 10225)
	r.recvrepeat(0.08)
	#r.recvuntil('> ')
	r.send("0\n")
	received = r.recvrepeat(0.08).decode("utf-8")
	msg = re.search(r'N_t: [0-9]+', received, re.MULTILINE)
	nonce = msg.string[msg.start():msg.end()]
	#print('nonce is:', nonce)
	target = nonce[5:]
	print('target:', target)

def f2():
	r = remote('cns.csie.org', 10225)
	received = r.recvrepeat(0.08)
	#r.recvuntil('> ')
	r.interactive()

if __name__ == "__main__":
	Thread(target = f1).start()
	Thread(target = f2).start()