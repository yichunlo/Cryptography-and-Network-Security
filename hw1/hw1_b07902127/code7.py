from pwn import *
import sympy
# sympy.mod_inverse(2, n)
r = remote('cns.csie.org', 10201)
r.recvuntil(': ')
#print("recvuntil:", s)
msg = r.recvline().strip()
#print("recvline:", msg)
r.sendlineafter('> ', '3')
r.sendlineafter('Command: ', msg)
#r.interactive()
#print("")
n = int(r.recv().decode("utf-8")[4:])
e = r.recv().decode("utf-8").split(" ")[2][:6]

r.send("1\n") # encrypt a constant
r.recv()
hex_2 = "32\n"
r.send(hex_2.encode("utf-8"))

rsa_val = int(r.recv().decode("utf-8"))
#print("rsa_val is:", rsa_val)
rsa_cypher = int(str(msg).split("||")[0][2:])
aes_cypher = str(msg).split("||")[1][:-1]
#print("aes cypher is:", aes_cypher)
print("")
decrypt_num = (rsa_cypher * rsa_val) % n
#print("decrypt_input is", decrypt_num)
s = str(decrypt_num) + "\n"
r.recv()

r.send("2\n") # decrypt!
r.recv()
r.send(s.encode("utf-8"))
trans = r.recv().decode("utf-8")
#print("trans is:", trans)

trans = int(trans, 16)
#print("after:", trans)
flag_val = (trans * sympy.mod_inverse(50, n)) % n
f = bytearray.fromhex(hex(flag_val)[2:])
flag = str(f)[12:len(str(f))-2]
print(flag)

'''============== solve flag2 ================='''

r.recv()
fl = flag.encode("utf-8")
plain_text = fl.hex()[96:]
length = int(len(plain_text))

padding = (32 - length) // 2
plain_text += "{:02x}".format(padding) * padding

#print("plain_text:", plain_text)
#print(fl.hex())

modify = flag[:len(flag)-4] + "getflag"

modify = modify.encode("utf-8")
modify = modify.hex()
#print("after hex:", modify)

plain_text_modified = modify[96:]
length = int(len(plain_text_modified))

padding = (32 - length) // 2
plain_text_modified += "{:02x}".format(padding) * padding
plain_text_modified = int(plain_text_modified, 16)


modify += "\n"
r.send("1\n")
r.recv()
r.send(modify)

modified_encrypt = r.recv().decode("utf-8")

#print("encrypt is:", modified_encrypt)
print(r.recv().decode("utf-8"))
#print("cypher_change:", aes_cypher[-32:])
#print("plain_text is:", plain_text)

cypher_to_change = int(aes_cypher[-32:], 16)
plain_text = int(plain_text, 16)
#print("cypher_to_change is:", cypher_to_change)
#print("plaintext to xor is:", plain_text)

x = cypher_to_change ^ plain_text
#print("x =", x)

#print("")

modified_c = x ^ plain_text_modified
modified_c = hex(modified_c)[2:]

#print(modified_c)
#print("")

Command = modified_encrypt + "||" + aes_cypher[:96] + str(modified_c) + "\n"
print(Command)
r.send("3\n")
r.recv()
r.send(Command)
received = r.recv().decode("utf-8")
print(received)
print("")
r.send("4\n")

