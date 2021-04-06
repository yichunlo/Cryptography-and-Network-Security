def construct_power():
	power = []
	gp = 1
	for _ in range(100001):
		power.append(gp)
		gp = gp * g % p
	return power

def get_power(v):
	ret = 0
	if v > 100000:
		mid = v // 2
		r = v - mid
		ret = get_power(mid)
		ret = ret * ret % p
		if r != mid:
			ret = ret * g % p
	else:
		ret = g_power_mod_p[v]
	return ret

def get_val(lines, cmp_val):
	for line in lines:
		val = int(line.split(",")[1])
		if get_power(val) == cmp_val:
			return val

def find_target(d1, d2, d3, q):
	for i in range(10):
		case1 = d1 + q * i
		for j in range(10):
			case2 = d2 + q * j
			for k in range(10):
				case3 = d3 + q * k
				a0 = 3 * case1 - 3 * case2 + case3
				a1 = -5 * case1 + 8 * case2 + 3 * case3
				a2 = case1 - 2 * case2 + case3
				if a0 > 0 and a1 > 0 and a2 > 0 and a1 % 2 == 0 and a2 % 2 == 0:
					if a0 < q:
						return a0
 
def val_to_string(target):
	flag = ""
	bi = [1, 2, 4, 8, 16, 32, 64, 128]
	counter = 0
	c = 0
	while target != 0:
		c += (target % 2) * bi[counter]
		counter += 1
		target //= 2
		if counter == 8:
			flag += chr(c)
			c = 0
			counter = 0
	flag += "C"
	return flag[::-1]


if __name__ == "__main__":

	p = 89884656743115795454248998571797095000269333286591366401471401401258315133319255635347152659731306864764553857219230273626406953968616926108939703546488998956315991156022292439572449964456177395053454057555571983259021089284480644521726081562919597934598089120908305128734644995347741254061371096110299607253
	q = 1177864165251363620544714577241785804395890016523
	g = 47404289179288640389640844879431558648177390184586696975897608942215464652597314280220784718274355624302810392733298227500137795030832063424482721066653824450798812915866522625944871510690868415392236131946395142854878295327233582076718493395282590329648437096343531800803152759220860390951680195514169026910
	c0 = 67235270739366149246517913026906986822201000914568189311605995137442341071140226723632477763824993550389797027354753029338275721113850881251609524028242882121410747873181290601020739373325270762302724782055890958096215360481254947681978132311423658278616166512037790332209093142905818887588473419430580169391
	c1 = 41639830728844168778345023563981565678419235844072022272176094997745791078756438136621312852254743630101402677797505543311764921085141226627234819401504835073100056684480036583320924069463452593476409171927651948416814723267153616400037995072014890636667901430318621563371637527526355042543724056317521667213
	c2 = 79033049103200938253679851712789184856929975282014007733809975662623115197028006186118091308319482599093892299109444978554812543639176257266894023822361605649548121911150914796346869367674202245029114740985634884407668184304861653924163734492388367809881403210736464448165140773278107663809426505140616354449
	
	g_power_mod_p = [] # save g^i mod p
	cmp_val1 = (c0 * c1 * c2) % p
	cmp_val2 = ((c0 % p) * (pow(c1, 2) % p) * (pow(c2, 4)) % p) % p
	cmp_val3 = ((c0 % p) * (pow(c1, 3) % p) * (pow(c2, 9)) % p) % p

	g_power_mod_p = construct_power()
	f1 = open("D1", "r")
	f2 = open("D2", "r")
	f3 = open("D3", "r")
	line1s = f1.readlines()
	line2s = f2.readlines()
	line3s = f3.readlines()
	d1 = get_val(line1s, cmp_val1)
	d2 = get_val(line2s, cmp_val2)
	d3 = get_val(line3s, cmp_val3)

	print("D1 is:", d1)
	print("D2 is:", d2)
	print("D3 is:", d3)

	target = find_target(d1, d2, d3, q)
	print("a0 is:", target)
	flag = val_to_string(target)
	print("flag is:", flag)