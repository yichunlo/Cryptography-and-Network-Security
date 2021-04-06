from pwn import *

X = []
get_token = "1\n"
logout = "4\n"
filled = "00000000000000000000000000000000"

def pad(pre, change, res, tail):
	padd = filled + pre + change + res + tail + "\n"
	r.send(padd.encode("utf-8"))
	received = r.recv().decode("utf-8")
	padding_check = re.search(r'PADDING ERROR : [a-z A-Z]+', received, re.MULTILINE)
	if padding_check:
		return True
	return False

def cbc(c, p):
	block = 6 - ((p-1) // 16)
	if p % 16 == 1:
		X.clear()
	cipher = c[:32*block]
	pos = (p-1) % 16 + 1
	idx = len(cipher) - 32 - (pos * 2)
	c_target = int(cipher[idx:idx+2], 16)
	x = 0

	pre = cipher[:idx]
	change = '{:02x}'.format(x)
	res = ""
	for v in X:
		res = ''.join(['{:02x}'.format(v ^ pos), res])
	tail = cipher[-32:]
	r.send("2\n")
	r.recv()
	
	padding_check = pad(pre, change, res, tail)

	while padding_check and x <= 255:
		x += 1
		if x == c_target:
			continue
		change = '{:02x}'.format(x)
		r.send("2\n")
		r.recv()
		padding_check = pad(pre, change, res, tail)

	r.send(logout.encode("utf-8"))
	r.recv().decode("utf-8")
	x_now = 0
	if x < 256:
		x_now = x ^ pos
		X.append(x_now)
	else:
		x_now = c_target ^ pos
		X.append(x_now)
	return chr(c_target ^ x_now)


if __name__ == "__main__":

	r = remote('cns.csie.org', 10202)
	print(r.recv().decode("utf-8"))
	# Get token first
	r.send(get_token.encode("utf-8"))
	token = r.recv().decode("utf-8")
	print(token)
	token = token[21:245]
	# start
	
	finish = 1;
	ans = ""
	while finish <= 80:
		ans += cbc(token[32:], finish);
		print("now is:", ans)
		finish += 1
	print("flag is:", ans[::-1])

