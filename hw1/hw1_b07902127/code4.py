from pwn import *

def get_str(match_obj):
	s = match_obj.string[match_obj.start():match_obj.end()]
	return s[5:]

def task_0(match_obj):
	ret = get_str(match_obj)
	print(ret)
	ret += "\n"
	r.send(ret.encode("utf-8"))
	return

def task_1(match_obj):
	ret = ""
	s = get_str(match_obj)
	for v in s:
		c = ord(v)
		if c >= ord('A') and c <= ord('Z'):
			if c >= ord('M'):
				c -= 13
			else:
				c += 13
		elif c >= ord('a') and c <= ord('z'):
			if c >= ord('m'):
				c -= 13
			else:
				c += 13
		ret += chr(c)
	print(ret)
	ret += "\n"
	r.send(ret.encode("utf-8"))
	return

def task_2(C1, M1, C2):
	c1 = get_str(C1)
	m1 = get_str(M1)
	c2 = get_str(C2)
	ret = ""
	key = 0
	for i in range(25):
		if c1[0].isupper() and (ord(c1[0]) - ord('A') + i) % 26 + ord('A') == ord(m1[0]):
			key = i
			break
		if c1[0].islower() and (ord(c1[0]) - ord('a') + i) % 26 + ord('a') == ord(m1[0]):
			key = i
			break
	for c in c2:
		if c.isupper():
			ret += chr((ord(c) - ord('A') + key) % 26 + ord('A'))
		elif c.islower():
			ret += chr((ord(c) - ord('a') + key) % 26 + ord('a'))
		else:
			ret += c
	print(ret)
	ret += '\n'
	r.send(ret.encode("utf-8"))
	return

def task_3(C1):
	ret = ""
	tr = []
	c1 = get_str(C1)
	for key in range(27):
		s = ""
		for c in c1:
			if c.isupper():
				s += chr((ord(c) - ord('A') + key) % 26 + ord('A'))
			elif c.islower():
				s += chr((ord(c) - ord('a') + key) % 26 + ord('a'))
			else:
				s += c
		tr.append(s)
		print(key, s)
	print("")
	print("Choose the answer!")
	idx = int(input())
	ret = tr[idx]
	print(ret)
	ret += "\n"
	r.send(ret.encode("utf-8"))
	return

def task_4(C1, M1, C2):
	c1 = get_str(C1)
	c2 = get_str(C2)
	m1 = get_str(M1)
	dic = {}
	idx = 0
	for c in c1:
		if c not in dic.keys():
			dic[c] = m1[idx]
		idx += 1
	ret = ""
	for c in c2:
		if c in dic.keys():
			ret += dic[c]
		else:
			ret += "*"
	print(ret)
	ans = input()
	r.send(ans)
	return

def task_5(C1, M1, C2):
	c1 = get_str(C1)
	c2 = get_str(C2)
	m1 = get_str(M1)
	l = int(len(m1))
	tr = []
	for i in range(2, l):
		s = ""
		if math.gcd(i, l) == 1:
			for j in range(l):
				s += c2[j*i % l]
			tr.append(s)
	for i in range(len(tr)):
		print(i, tr[i])
	idx = int(input("Choose the answer:"))
	print(tr[idx])
	ret = tr[idx] + "\n"
	r.send(ret.encode("utf-8"))
	return

def trans_task(match_obj):
	s = get_str(match_obj)
	for i in s:
		if i.isdigit():
			return int(i)
	return 0

r = remote('cns.csie.org', 10200)
line = r.recv()
start = False
while line:
	msg = line.decode("utf-8")
	print(msg)
	# re.search(pattern, string, flags)
	m1 = re.search(r'm1 = [a-zA-Z ]+', msg, re.MULTILINE) 
	c1 = re.search(r'c1 = [a-zA-Z ]+', msg, re.MULTILINE)
	c2 = re.search(r'c2 = [a-zA-Z ]+', msg, re.MULTILINE)
	round_n = re.search(r'### [a-z0-9 ]+ ###', msg, re.MULTILINE)

	if start == False and m1:
		start = True
		task_0(m1)
	elif round_n and start:
		task = trans_task(round_n)
		if task == 1:
			task_1(c1)
		elif task == 2:
			task_2(c1, m1, c2)
		elif task == 3:
			task_3(c1)
		elif task == 4:
			task_4(c1, m1, c2)
		elif task == 5:
			task_5(c1, m1, c2)
	line = r.recv()

