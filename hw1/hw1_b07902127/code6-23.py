from pwn import *

get_token = "1\n"
logout = "4\n"
IV = "796f75725f65766572796461795f6976"
p2 = "5f77616e7c7c69737669703a317c7c69"
c1 = "254d096f3657ed543d5b6ee7d22ba586"
c3 = "19be85e7afd1f8b4a7e0f7db79cb6c6b"
left = "4452aa7916d9ad9b9f35e34098aef66e101a2d9f3bc2a070820c62a98fdf4de5ac58236cb5ccd4a0c4fdad7646d0c104"

def login():
	r.send("2\n")
	r.recv()

def pad(pre, change, tail):
	padd = IV + c1 + pre + change + tail + c3 + "\n"
	r.send(padd.encode("utf-8"))
	received = r.recv().decode("utf-8")
	padding_check = re.search(r'PADDING ERROR : [a-z A-Z]+', received, re.MULTILINE)
	if padding_check:
		return True
	return False

def get_flag():
	r.send("2\n")
	print(r.recv().decode("utf-8"))
	r.send("???\n")
	r.recv()
	r.send("???\n")
	r.recv()
	r.send("1\n")
	print(r.recv().decode("utf-8"))
	r.send("4\n")
	r.recv()
	r.send("3\n")
	exit()

def cbc():
	X = []
	B = []
	idx = 1
	tar = 0
	pre = ""
	while idx <= 16:
		x = 0
		iteration = f"iteration {idx}..."
		print(iteration)
		pre = "00" * (16 - idx)
		change = "00"
		tail = ""
		for v in X:
			tail = "".join(["{:02x}".format(v ^ idx), tail])
		login()
		
		padding_check = pad(pre, change, tail)
		while padding_check and x < 255:
			x += 1
			change = "{:02x}".format(x)
			login()
			padding_check = pad(pre, change, tail)

		r.send(logout.encode("utf-8"))
		r.recv()
		x_now = x ^ idx
		id_ = 2 * (16 - idx)
		tar = int(p2[id_:id_+2], 16)
		X.append(x_now)
		B.append(x_now ^ tar)
		idx += 1
	block = ""
	for v in B:
		block = "".join(["{:02x}".format(v), block])
	return block

if __name__ == "__main__":

	r = remote('cns.csie.org', 10202)
	print(r.recv().decode("utf-8"))
	r.send(get_token.encode("utf-8"))
	token = r.recv().decode("utf-8")
	print(token)
	token = token[21:245]

	cbc_c2 = cbc()
	login()

	# cbc_c2's first four bytes is 11010011, 11011101, 11110011, 01000110
	modify = "{:02x}".format(128) + "{:02x}".format(156) + "{:02x}".format(140)
	key = IV + c1 + modify + cbc_c2[6:] + c3 + left + "\n"
	r.send(key.encode("utf-8"))
	#print("key:", key)
	#r.send(attempt_key.encode("utf-8"))

	received = r.recv().decode("utf-8")
	uni_check = re.search(r'Unicode Decode Error', received)

	if uni_check:
		for i in range(128, 256):
			for j in range(150, 256):
				for k in range(137, 256):
					pre = "{:02x}".format(i) + "{:02x}".format(j) + "{:02x}".format(k)
					tail = cbc_c2[6:]
					attempt_key = IV + c1 + pre + tail + c3 + left + "\n"
					login()
					r.send(attempt_key.encode("utf-8"))
					received = r.recv().decode("utf-8")
					uni_check = re.search(r'Unicode Decode Error', received)
					if uni_check:
						print("i, j, k is:", i, j, k)
					else:
						print("success key:", attempt_key)
						get_flag()
	else:
		get_flag()





	
