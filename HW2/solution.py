import myntl
import lfsr
import hw2_helper as helper
import client
import math
import random
from Crypto.Cipher import Salsa20

n,t = client.getQ1()

# n ->  394 , t -> 49 The number of elements int he group is the count of the numbers
# that are relatively prime with 394 -> phi(394)

client.checkQ1a(myntl.phi(n))
ansA = myntl.phi(n)

print("Answer of q1a -",ansA)

# In order to be a generator a number must be relatively prime with n, let's say that number is 3

ansB = 3
client.checkQ1b(3)
print("Answer of q1b -", ansB) 

# A subgroup n will contain elements in form of 49*k + n (n < 49)
# so all of them is relatively prime with 49 so the answer is 49

ansC = 49
client.checkQ1c(ansC)
print("Answer of q1c -", ansC)

def getLastDigitOfBinary(e):
    binary = bin(e)[2:]
    a = len(binary)
    mask = e >> a - 1
    k = e & mask
    return k

e,c = client.getQ2()

# print("e=",e)
# print()
# print("c=",c)
# print()
p = 129711420978537746088867309342132426785901989689874594485896371555019986573705426172788805726178509467748040679168734095884433597017604012172054368990172572715857537355524013819947862920969421702067385445122242673064958991968666138544380365520456029952414962028711806175784928131826127885820644091951344318387
q = 174066672405085972657808881778978520582809763235147358374332409966322987290745416405220414323004782906757362579157117914494927198442645581197584273451379119673753279114693557694861941678350357667191083878100828920198503774539271289263633646647364198130180304138099281532660260760636194367337370132530987351081
n = p*q

def right_to_left_binaryExpansion(a,e,n):
    x = 1
    y = a
        
    while e != 0:
        if getLastDigitOfBinary(e) == 1:
            x = x*y % n
        y = y*y % n
        e = e >> 1
    
    return x % n
inv_e = myntl.modinv(e,n)
m = right_to_left_binaryExpansion(c,inv_e,n)

uni = m.to_bytes((m.bit_length()+7)//8,byteorder='big')
#print(uni)
uni = uni.decode('utf-8','ignore')

print(uni)
client.checkQ2(str(uni))



secret = 14656892184006070584
ctext = b"Vbq\x8a\xe3\xb7Rgl-\x14\x8bNS\xeb\x01\xbd\xdf\x1f\x14\x84{\xdanX,\xa5\x98RM\x98\r\xd7\x1e\x9dO\x14\xa7\x8cX\xcb\xad\xf2\xc9\x1f\xc1]\xef\x908I\xe0\xcf\x10%.ulh\xe7\xd6\x9d<\xb9a\xda\xb0\xa2d\xe9\x18\xef9\x99ttP\x9blw\x0e\xe7\xd6\xbb1\xf4?\x16kf\x87\x19\xbe\x94O\xe8\x1d\x08\xe4\xff)\x99']\xda\x191=|H"
key = secret.to_bytes(32,byteorder='big')
ctext_nonce = ctext[:8]
ciphertext = ctext[8:]
cipher = Salsa20.new(key, nonce=ctext_nonce)
dtext = cipher.decrypt(ciphertext)

print(dtext.decode('utf-8','ignore'))
print()

ctext = b'\eda\x01q+]\x8c\x06[\xa2/\xb8\xcaX\x1f\x8f:\xc97\x0f)\xa5\x84Y\t\xdc\x07\xd2L\xb3V\x14\xad\x8bU\x99\xa3\xf2\x9dK\xc8V\xab\xdd\nS\xe9\xcf\x05$r,\t<\x9e\xd0\x9b<\xbcx\x99\xaf\xed7\xf9\x13\xff9\x88r\\\x9b}>\x1d\xeb'
key = secret.to_bytes(32,byteorder='big')
#ctext_nonce = ctext[:8]
ciphertext = ctext[5:]
cipher = Salsa20.new(key, nonce=ctext_nonce)
dtext = cipher.decrypt(ciphertext)

print(dtext.decode('UTF-8','ignore'))
print()

ctext = b'ea,\x14\x88NW\xbfh\xb9\xcdX\x0f\x83}\xc0cX5\xa5\x9e\x1e^\xd0\x03\xc5\x1e\xa3U@\xa1\x85H\xc0'

key = secret.to_bytes(32,byteorder='big')
#ctext_nonce = ctext[:8]
ciphertext = ctext[1:]
cipher = Salsa20.new(key, nonce=ctext_nonce)
dtext = cipher.decrypt(ciphertext)

print(dtext.decode('UTF-8','ignore'))


#q4

#a

n = 1593089977489628213419978935847037520292814625191902216371975
a = 1085484459548069946264190994325065981547479490357385174198606
b = 953189746439821656094084356255725844528749341834716784445794
possibleCount, x, y = myntl.egcd(a,n)

if possibleCount == 1:
    inv_a = myntl.modinv(a,n)
    x = inv_a * b % n
    print("There is only one solution and that is:",x)
else:
    if b % possibleCount == 0:
        new_n = n//possibleCount
        a = a//possibleCount
        b = b//possibleCount
           
        #print(myntl.gcd(a,new_n))
        
        inv_a = myntl.modinv(a,new_n)
        x = inv_a * b % new_n
        
        k = x
        print("There are",possibleCount,"solutions, and they are:",end=" ")
        while k<n:
            print(k,",",sep="",end=" ")
            k += new_n
        print()
    else:
        print("There is no solution.")
  
  
#b
n = 1604381279648013370121337611949677864830039917668320704906912
a = 363513302982222769246854729203529628172715297372073676369299
b = 1306899432917281278335140993361301678049317527759257978568241
possibleCount, x, y = myntl.egcd(a,n)

if possibleCount == 1:
    inv_a = myntl.modinv(a,n)
    x = inv_a * b % n
    print("There is only one solution and that is:",x)
else:
    if b % possibleCount == 0:
        new_n = n//possibleCount
        a = a//possibleCount
        b = b//possibleCount
           
        #print(myntl.gcd(a,new_n))
        
        inv_a = myntl.modinv(a,new_n)
        x = inv_a * b % new_n
        
        k = x
        print("There are",possibleCount,"solutions, and they are:",end=" ")
        while k<n:
            print(k,"",sep=",",end=" ")
            k += new_n
        print()
    else:
        print("There is no solution.")


#c

n = 591375382219300240363628802132113226233154663323164696317092
a = 1143601365013264416361441429727110867366620091483828932889862
b = 368444135753187037947211618249879699701466381631559610698826

possibleCount = myntl.gcd(a,n)

if possibleCount == 1:
    inv_a = myntl.modinv(a,n)
    x = inv_a * b % n
    print("There is only one solution and that is:",x)
else:
    if b % possibleCount == 0:
        new_n = n//possibleCount
        a = a//possibleCount
        b = b//possibleCount
           
        #print(myntl.gcd(a,new_n))
        
        inv_a = myntl.modinv(a,new_n)
        x = inv_a * b % new_n
        
        k = x
        print("There are",possibleCount,"solutions, and they are:",end=" ")
        while k<n:
            print(k,",",sep="",end=" ")
            k += new_n
        print()
    else:
        print("There is no solution.")
    
#d

n = 72223241701063812950018534557861370515090379790101401906496
a = 798442746309714903219853299207137826650460450190001016593820
b = 263077027284763417836483401088884721142505761791336585685868

possibleCount, x, y = myntl.egcd(a,n)

if possibleCount == 1:
    inv_a = myntl.modinv(a,n)
    x = inv_a * b % n
    print("There is only one solution and that is:",x)
else:
    if b % possibleCount == 0:
        new_n = n//possibleCount
        a = a//possibleCount
        b = b//possibleCount
           
        #print(myntl.gcd(a,new_n))
        
        inv_a = myntl.modinv(a,new_n)
        x = inv_a * b % new_n
        
        k = x
        print("There are",possibleCount,"solutions, and they are:",end=" ")
        while k<n:
            print(k,",",sep="",end=" ")
            k += new_n
        print()
    else:
        print("There is no solution.")
        

#q5 
#1
length = 2**7
keystream = []
for i in range(2**7):
    keystream.append(0)
    
C = [0]*7
C[6] = C[5] = C[4] = C[1] = C[0] = 1

S = [0]*6
    
for i in range(0,6):            # for random initial state
    S[i] = random.randint(0, 1)
    
for i in range(0,length):
     keystream[i] = lfsr.LFSR(C, S)

per = lfsr.FindPeriod(keystream)
if per == 2**6 - 1:
    print("Maximum period sequence achieved for x6 + x5 + x4 + x + 1:",per)
else:
    print ("First period for x6 + x5 + x4 + x + 1:", per, "which is smaller than",2**6-1,"so it is not maximum")

#2
length = 2**7
keystream = []
for i in range(2**7):
    keystream.append(0)
    
C = [0]*7
C[6] = C[2] = C[0] = 1

S = [0]*6
    
for i in range(0,6):            # for random initial state
    S[i] = random.randint(0, 1)
    
for i in range(0,length):
     keystream[i] = lfsr.LFSR(C, S)
     
per = lfsr.FindPeriod(keystream)
if per == 2**6 - 1:
    print("Maximum period sequence achieved for x6 + x2 + 1:",per)
else:
    print ("First period for x6 + x2 + 1:", per, "which is smaller than",2**6-1,"so it is not maximum")

#3
length = 2**6
keystream = []
for i in range(2**6):
    keystream.append(0)
    
C = [0]*6
C[5] = C[3] = C[0] = 1

S = [0]*5
    
for i in range(0,5):            # for random initial state
    S[i] = random.randint(0, 1)
    
for i in range(0,length):
     keystream[i] = lfsr.LFSR(C, S)
     
per = lfsr.FindPeriod(keystream)
if per == 2**5 - 1:
    print("Maximum period sequence achieved for x5 + x3 + 1:",per)
else:
    print ("First period for x5 + x3 + 1:", per, "which is smaller than",2**5-1,"so it is not maximum")


#q6

x1 = [0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1,
1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1,
0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0]

x2 = [0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1,
1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1]

x3 = [1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1,
1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0,
0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1]


print ("L and C(x): ", lfsr.BM(x1), "len x1",len(x1))
print ("L and C(x): ", lfsr.BM(x2), "len x2",len(x2))
print ("L and C(x): ", lfsr.BM(x3), "len x3",len(x3))

#Expected linear complexity of a random sequence E(L(sn)) ≈ n/2 + 2/9.
# For x1 L = 45 and n/2 + 2/9 ~= 44.7 so it can be considered as random
# For x2 L = 29 and n/2 + 2/9 ~= 43.7 so it can be considered as predictable
# For x3 L = 37 and n/2 + 2/9 ~= 51.2 so it can be accepted as preditable


"""
ctext = [1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1,
1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0,
1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0,
0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1,
1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1,
0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0,
0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1,
0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0,
1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1,
0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1,
1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1,
0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0,
1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0,
0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1,
0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0,
1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1,
1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0,
0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0,
0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1,
1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1,
0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0,
0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0,
1, 1, 0, 0, 1, 1, 1, 1, 1, 1]

known_keystream = ctext[len(ctext)-84:]
known_ctext = helper.ASCII2bin("Atil Utku Ay")



keystream = []

for i in range(len(known_ctext)):
    if known_keystream[i] == known_ctext[i]:
        keystream.append(1)
    else:
        keystream.append(0)
        
print ("L and C(x): ", lfsr.BM(keystream), "len x1",len(keystream))
decrypted = []
kyyy = [1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]
for i in range(len(ctext)):
    if keystream[i%len(kyyy)] == ctext[i]:
        decrypted.append(0)
    else:
        decrypted.append(1)
        
#print(decrypted)


#print(lfsr.LFSR(ctext,kyyy))

binary = ""
totalText = ""
#print(len(ctext))
for i in range(len(decrypted)):   
    binary += str(decrypted[i])
    if i%7 == -1:
        totalText += helper.bin2ASCII(binary)
        binary = ""
    elif i == len(decrypted) -1:
        totalText += helper.bin2ASCII(binary)
        
print(totalText)
"""


