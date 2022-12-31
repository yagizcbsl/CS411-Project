import math
import random
import fractions

# This is method to compute Euler's function
# The method here is based on "counting", which is not good for large numbers in cryptography
def phi(n):
    amount = 0
    for k in range(1, n + 1):
        if math.gcd(n, k) == 1:
            amount += 1
    return amount

# The extended Euclidean algorithm (EEA)
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

# Modular inverse algorithm that uses EEA
def modinv(a, m):
    if a < 0:
        a = m+a
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

# You can use the the following variables for encoding an decoding of English letters    
lowercase = {'a':0, 'b':1, 'c':2, 'd':3, 'e':4, 'f':5, 'g':6, 'h':7, 'i':8,
         'j':9, 'k':10, 'l':11, 'm':12, 'n':13, 'o':14, 'p':15, 'q':16,
         'r':17, 's':18,  't':19, 'u':20, 'v':21, 'w':22, 'x':23, 'y':24,
         'z':25}

uppercase ={'A':0, 'B':1, 'C':2, 'D':3, 'E':4, 'F':5, 'G':6, 'H':7, 'I':8,
         'J':9, 'K':10, 'L':11, 'M':12, 'N':13, 'O':14, 'P':15, 'Q':16,
         'R':17, 'S':18,  'T':19, 'U':20, 'V':21, 'W':22, 'X':23, 'Y':24,
         'Z':25}

inv_lowercase = {0:'a', 1:'b', 2:'c', 3:'d', 4:'e', 5:'f', 6:'g', 7:'h', 8:'i',
         9:'j', 10:'k', 11:'l', 12:'m', 13:'n', 14:'o', 15:'p', 16:'q',
         17:'r', 18:'s', 19:'t', 20:'u', 21:'v', 22:'w', 23:'x', 24:'y',
         25:'z'}

inv_uppercase = {0:'A', 1:'B', 2:'C', 3:'D', 4:'E', 5:'F', 6:'G', 7:'H',
                 8:'I', 9:'J', 10:'K', 11:'L', 12:'M', 13:'N', 14:'O', 15:'P',
                 16:'Q', 17:'R', 18:'S', 19:'T', 20:'U', 21:'V', 22:'W', 23:'X',
                 24:'Y', 25:'Z'}

letter_count = {'A':0, 'B':0, 'C':0, 'D':0, 'E':0, 'F':0, 'G':0, 'H':0, 'I':0,
         'J':0, 'K':0, 'L':0, 'M':0, 'N':0, 'O':0, 'P':0, 'Q':0,
         'R':0, 'S':0,  'T':0, 'U':0, 'V':0, 'W':0, 'X':0, 'Y':0, 'Z':0}


# Note that encyrption and decryption algorithms are slightly different for
# Turkish texts
turkish_alphabet ={'A':0, 'B':1, 'C':2, 'Ç':3, 'D':4, 'E':5, 'F':6, 'G':7, 'Ğ':8, 'H':9, 'I':10,
         'İ': 11, 'J':12, 'K':13, 'L':14, 'M':15, 'N':16, 'O':17, 'Ö':18, 'P':19, 
         'R':20, 'S':21,  'Ş':22, 'T':23, 'U':24, 'Ü':25, 'V':26, 'Y':27,
         'Z':28}

inv_turkish_alphabet = {0:'A', 1:'B', 2:'C', 3:'Ç', 4:'D', 5:'E', 6:'F', 7:'G', 8:'Ğ', 9:'H',
              10:'I', 11:'İ', 12:'J', 13:'K', 14:'L', 15:'M', 16:'N', 17:'O', 18:'Ö',
              19:'P', 20:'R', 21:'S',  22:'Ş', 23:'T', 24:'U', 25:'Ü', 26:'V',
              27:'Y', 28:'Z'}

# Affine cipher encryption and decryption routines only for English texts
def Affine_Enc(ptext, key):
    plen = len(ptext)
    ctext = ''
    for i in range (0,plen):
        letter = ptext[i]
        if letter in lowercase:
            poz = lowercase[letter]
            poz = (key.alpha*poz+key.beta)%26
            #print poz
            ctext += inv_lowercase[poz]
        elif letter in uppercase:
            poz = uppercase[letter]
            poz = (key.alpha*poz+key.beta)%26
            ctext += inv_uppercase[poz]
        else:
            ctext += ptext[i]
    return ctext

def Affine_Dec(ptext, key):
    plen = len(ptext)
    ctext = ''
    for i in range (0,plen):
        letter = ptext[i]
        if letter in lowercase:
            poz = lowercase[letter]
            poz = (key.gamma*poz+key.theta)%26
            #print poz
            ctext += inv_lowercase[poz]
        elif letter in uppercase:
            poz = uppercase[letter]
            poz = (key.gamma*poz+key.theta)%26
            ctext += inv_uppercase[poz]
        else:
            ctext += ptext[i]
    return ctext

def countLetters(ctext,letter_count):
    for i in range(len(ctext)):
        letter = ctext[i]
        flag = True
        if letter in lowercase:
            letter = letter.upper()
        elif letter not in uppercase:
            flag = False
        if flag:
            letter_count[letter] += 1
        
    return letter_count
            

# key object for Affine cipher
# (alpha, beta) is the encryption key
# (gamma, theta) is the decryption key
class key(object):
    alpha=0
    beta=0
    gamma=0
    theta=0

# A simple example
""""
key.alpha = 3
key.beta = 17
key.gamma = modinv(key.alpha, 26) # you can compute decryption key from encryption key
key.theta = 26-(key.gamma*key.beta)%26

ptext = "Hello Crypto World"
ctext = Affine_Enc(ptext, key)
dtext = Affine_Dec(ctext, key)
print("plaintext: ", ptext)
print("ciphertext: ", ctext)
print("plaintext: ", dtext)
"""

# Question 1

print("\nQuestion - 1 Shift Cipher")

ciphertext1 = "NGZZK"

# If we use the the implemented Affine_Dec function and make the key.gamma = 1 and key.theta to shift amount it will be shift cipher

possible_words = []

for i in range(26):
    key.gamma = 1
    key.theta = i
    word = Affine_Dec(ciphertext1,key)
    possible_words.append(word)

print(possible_words)
print("\nMeaningful words are SLEEP and BUNNY")

#When the possible_words printed it can be seen that there are 2 meaningful words, which are 'SLEEP' and 'BUNNY'

#Question 2 

print("\nQuestion - 2 Affine Cipher")

ciphertext2 = "ZJOWMJ ZJGC BS UEVRSCC, KSZ ZJSFS GC USZJOV GR GZ."

letterCounts = countLetters(ciphertext2,letter_count)
print(letterCounts) # Two most frequent letters are 'S' : 18 and 'Z' : 25

#One of the most frequent letter is 'T' and there is a high probability that other one is 'E'


#Possible scenario - 1 --- 'S' and 'T', 'Z' and 'E' matched key.gamma* 18 + key.theta = 19 % 26 and key.gamma*25 + key.theta = 4 % 26
key.gamma = 9
key.theta = 13

word = Affine_Dec(ciphertext2,key)
print(word)

#Possible scenario - 2 --- 'S' and 'E', 'Z' and 'T' matched key.gamma* 18 + key.theta = 4 % 26 and key.gamma*25 + key.theta = 19 % 26
key.gamma = 17
key.theta = 10

word = Affine_Dec(ciphertext2,key)
print(word)

#Scenario 2 produced a meaningful word which is "THOUGH THIS BE MADNESS, YET THERE IS METHOD IN IT." so decryption key is -> gamma (inverse of alpha) is 17 and theta (inverse of beta) is 10

#Now encryption key needs to be found
#It is known that 19*key.alpha + key.beta = 25 % 26 and 4*key.alpha + key.beta = 18 % 26

key.alpha = 23
key.beta = 4

encrypted = Affine_Enc(word,key)

if encrypted == ciphertext2:
    print("Encrypted:",encrypted)
    print("It matches with the given ciphertext.")
    

#Question - 3
#There are 28*28 possible (double space is counted as well) bigrams so the modulus is 28*28 = 784 and key space is the count of the numbers that are relatively prime with 784 which is 328


#Question -4
#It is secure against the letter frequency analysis. Explanation with example: 

#Question 5

print("\nQuestion - 5 Affine Cipher on Bigrams")

extended_chars = {'A':0, 'B':1, 'C':2, 'D':3, 'E':4, 'F':5, 'G':6, 'H':7, 'I':8, 'J':9,
                  'K':10, 'L':11, 'M':12, 'N':13, 'O':14, 'P':15, 'Q':16, 'R':17, 'S':18,
                  'T':19, 'U':20, 'V':21, 'W':22, 'X':23, 'Y':24, 'Z':25, '.':26, ' ':27}

def getKeyFromValue(dic,val):
    for k,v in dic.items():
        if v == val:
            return k
    return None

def encodeBigram(bigram):
    if len(bigram) != 2:
        print("Length of a bigram must be 2.")
        return
    firstChar = bigram[0].upper()
    secondChar = bigram[1].upper()
    
    return 28 * extended_chars[firstChar] + extended_chars[secondChar]

def decodeBigram(encode):
    secondCode = encode % 28
    firstCode = encode // 28
    
    res = ""
    
    res += getKeyFromValue(extended_chars,firstCode)
    res += getKeyFromValue(extended_chars,secondCode)
    
    return res

    
def Affine_Enc_bigram(bigram, key):
    encode = encodeBigram(bigram)
    encryptedEncode = (key.alpha*encode + key.beta) % 784
    encryptedBigram = decodeBigram(encryptedEncode)
    return encryptedBigram

def Affine_Dec_bigram(bigram, key):
    encode = encodeBigram(bigram)
    decryptedEncode = (key.gamma*encode + key.theta) % 784
    decryptedBigram = decodeBigram(decryptedEncode)
    return decryptedBigram
 
#Last character is '.' and plen = 1 (mod 2) so last bigram must be .X

#print(encodeBigram(".X"),encodeBigram("YT"))

#key.gamma = 573
#key.theta = 0

ciphertext3 = "ZDZUKEO.AANDOGIJTLNEKEPHZUQDX NDS VLNDJGQLYDVSBU.DER.K.UYT"
possible_ptexts = []

for i in range(784):
    if math.gcd(i,784) == 1:
        key.gamma = i;
        key.theta = (751 - key.gamma * 691) % 784 
        plainText = ""
        for j in range(len(ciphertext3)):
            if j%2 == 0:
                plainText += Affine_Dec_bigram(ciphertext3[j:j+2],key)
        possible_ptexts.append(plainText)
        #print(plainText,key.gamma,key.theta)

#print(possible_ptexts,len(possible_ptexts))

#It was known that last 2 character encrypted to the "YT" FROM ".X". This is because it can be said that
# 691*key.gamma + key.theta = 751 % 784. So each possible key.gamma,key.theta pair have been tried (336 of them, gamma's are the ones that are relatively prime with 784)
# and it is observed that only meaningful plain text is "I HAVE COME TO BELIEVE THAT THE WHOLE WORLD IS AN ENIGMA." and key.gamma,key.theta pair is 89,404

key.gamma = 89
key.theta = 404

#Decryption key pair is known so encrpytion key can be found
key.alpha = modinv(key.gamma,784)
key.beta = (691 - 751 * key.alpha) % 784

plaintext3 = "I HAVE COME TO BELIEVE THAT THE WHOLE WORLD IS AN ENIGMA."


if len(plaintext3) % 2 == 1:
    plaintext3+="X"

ctext3 = ""    

for j in range(len(plaintext3)):
    if j%2 == 0:
        ctext3 += Affine_Enc_bigram(plaintext3[j:j+2],key)
if ctext3 == ciphertext3:
    print("Encryption key is working ciphertexts are matching with each other.")
    print(ctext3)


#Question 7

print("\nQuestion - 6 Vigene Cipher")

ciphertext4 = "JR WYDUGQ AR LRG BTFWB’U UECDC YVTF S CYVNE LY JVS QZYWYDCJC, CAD FAC NRGQ KZTRAB MXYVTRAXIYY, YK SH GHC DOXRL DDYQES UWBG GIJLSPT UN SXF FILCSPT DMOX VB TFW RGNVC SXF YULYO QS TFW CGN. TFW GKQE PGYOF SCWWGQ TMG XCERMO PQE HGK BQYLGFQ INIR, SXF GO FAWURLD ZO YNS GF DGERMJ VGFT FAC DEOYV CJBUJVOTF SFGENQ CMDVKQE UADJ GHC VYQEWYQC QE SUWOR GHC TBKP-A-ZJKE SRME DJR LMO WCATCD. RG EEAGSNRD DJYO FIBW DQ FIBW LGGWCWX VUE TSBKBUQ GLLRCRK KPQ MSDDKCLGWN VUE FSJCEDQ LRCG IL JOCYIRQ VQQGCV YPYY GF RKF MGFN. DRTUWOP N GPSXF CIYFY CAD Y UOPGRC-LKDYE NAVGQ HGYR YVTF TYQXS USC UCAAW PQE A FSVH N DMROP GO USVM NBPWKUG, YCL RG RSQSIGQ IR OSVU TPWZKQARAYP. UIQ ZOCIY YJWU UULY VQBSCDI CG HGK CKQEQ. ZO FVD LGD MAOU ORCG TM VY YVTF LRQFE YJWU NNB ZKPQS, YFN YUEL, LY JVS CPMKGEB NSUVOL, GXG NRK KOGZEB DSCOLC LY DEUQZ KINILKD VUE ZGYMF OL LRG GAZDO, JR LSJMJRD YOKA YIIW K HEIEZDGAEB ZYTFE, ZSBGYY KACUVNE LRG CIYFY UGOMD. RG JARURGQ TFW OCFY USVM BF RZO QGHCJ SP SRMFD QS HGE, KPQ FMJ DJR FGJCV GIKW BGNLGROF GHYL RKF WYDU YNS BAPHRRCFD HEOK LRCG OD GDJRR KWX. JR EVHOTVELUOF N MMEOPGAPQ ZCAG MX CJNMC LRCG HC KRQHLB OKNX SM MXEBURZVA. GHC KGGNT ZMBUG TFJYWTH RZO UXIL GP JVS DGBGUEYV SP GILQ LGNDQ, SXF UE NSEURD YFN OBPNWN JVS ZJYPMEB XKER WGLR JVS FSXFXEPURKRF."
trimmed_ctex = ciphertext4.replace(" ","")
trimmed_ctex = trimmed_ctex.replace(",","")
trimmed_ctex = trimmed_ctex.replace(".","")
trimmed_ctex = trimmed_ctex.replace("-","")
trimmed_ctex = trimmed_ctex.replace("’","")
trimmed_ctex = trimmed_ctex.replace("\n","")
#print(trimmed_ctex)


def shiftbyN(ctext,shift):
    ctext = shift* " " + ctext
    return ctext

def countCoincidences(ctext,shifted):
    count = 0
    for i in range(len(ctext)):
        if ctext[i] == shifted[i]:
            count += 1
    return count

for i in range(1,100):
    shifted = shiftbyN(trimmed_ctex,i)
    count = countCoincidences(trimmed_ctex,shifted)
    #print(count,i)
    
#key length 6
    
subtext1 = trimmed_ctex[::6]
subtext2 = trimmed_ctex[1::6]
subtext3 = trimmed_ctex[2::6]
subtext4 = trimmed_ctex[3::6]
subtext5 = trimmed_ctex[4::6]
subtext6 = trimmed_ctex[5::6]
"""
print(subtext1)
print()
print(subtext2)
print()
print(subtext3)
print()
print(subtext4)
print()
print(subtext5)
print()
print(subtext6)
print()
"""

letter_count = {'A':0, 'B':0, 'C':0, 'D':0, 'E':0, 'F':0, 'G':0, 'H':0, 'I':0,
         'J':0, 'K':0, 'L':0, 'M':0, 'N':0, 'O':0, 'P':0, 'Q':0,
         'R':0, 'S':0,  'T':0, 'U':0, 'V':0, 'W':0, 'X':0, 'Y':0, 'Z':0}

for i in range(len(subtext1)):
    letter_count[subtext1[i]] += 1
    
print(1,letter_count) # 'G' is the most common character by 25 occurences, it might be match with 'E', shift amount uppercase['E'] - uppercase['G'] 
key.gamma = 1;
key.theta = uppercase['E'] - uppercase['G']
subtext1 = Affine_Dec(subtext1,key)

letter_count = {'A':0, 'B':0, 'C':0, 'D':0, 'E':0, 'F':0, 'G':0, 'H':0, 'I':0,
         'J':0, 'K':0, 'L':0, 'M':0, 'N':0, 'O':0, 'P':0, 'Q':0,
         'R':0, 'S':0,  'T':0, 'U':0, 'V':0, 'W':0, 'X':0, 'Y':0, 'Z':0}

for i in range(len(subtext2)):
    letter_count[subtext2[i]] += 1
    
print(2,letter_count) # 'G' is the most common character by 24 occurences, it might be match with 'E', shift amount uppercase['E'] - uppercase['G'] 
key.gamma = 1;
key.theta = uppercase['E'] - uppercase['R']
subtext2 = Affine_Dec(subtext2,key)

letter_count = {'A':0, 'B':0, 'C':0, 'D':0, 'E':0, 'F':0, 'G':0, 'H':0, 'I':0,
         'J':0, 'K':0, 'L':0, 'M':0, 'N':0, 'O':0, 'P':0, 'Q':0,
         'R':0, 'S':0,  'T':0, 'U':0, 'V':0, 'W':0, 'X':0, 'Y':0, 'Z':0}

for i in range(len(subtext3)):
    letter_count[subtext3[i]] += 1
    
print(3,letter_count) # 'E' is the most common character by 25 occurences, it might be match with 'E', shift amount uppercase['E'] - uppercase['E'] 


letter_count = {'A':0, 'B':0, 'C':0, 'D':0, 'E':0, 'F':0, 'G':0, 'H':0, 'I':0,
         'J':0, 'K':0, 'L':0, 'M':0, 'N':0, 'O':0, 'P':0, 'Q':0,
         'R':0, 'S':0,  'T':0, 'U':0, 'V':0, 'W':0, 'X':0, 'Y':0, 'Z':0}

for i in range(len(subtext4)):
    letter_count[subtext4[i]] += 1
    
print(4,letter_count) # 'C' is the most common character by 20 occurences, it might be match with 'E', shift amount uppercase['E'] - uppercase['F'] 
key.gamma = 1;
key.theta = uppercase['E'] - uppercase['C']
subtext4 = Affine_Dec(subtext4,key)

letter_count = {'A':0, 'B':0, 'C':0, 'D':0, 'E':0, 'F':0, 'G':0, 'H':0, 'I':0,
         'J':0, 'K':0, 'L':0, 'M':0, 'N':0, 'O':0, 'P':0, 'Q':0,
         'R':0, 'S':0,  'T':0, 'U':0, 'V':0, 'W':0, 'X':0, 'Y':0, 'Z':0}

for i in range(len(subtext5)):
    letter_count[subtext5[i]] += 1
    
print(5,letter_count) # 'W' is the most common character by 20 occurences, it might be match with 'E', shift amount uppercase['E'] - uppercase['W'] 
key.gamma = 1;
key.theta = uppercase['E'] - uppercase['W']
subtext5 = Affine_Dec(subtext5,key)

letter_count = {'A':0, 'B':0, 'C':0, 'D':0, 'E':0, 'F':0, 'G':0, 'H':0, 'I':0,
         'J':0, 'K':0, 'L':0, 'M':0, 'N':0, 'O':0, 'P':0, 'Q':0,
         'R':0, 'S':0,  'T':0, 'U':0, 'V':0, 'W':0, 'X':0, 'Y':0, 'Z':0}

for i in range(len(subtext6)):
    letter_count[subtext6[i]] += 1
    
print(6,letter_count) # 'O' is the most common character by 20 occurences, it might be match with 'E', shift amount uppercase['E'] - uppercase['O'] 
key.gamma = 1;
key.theta = uppercase['E'] - uppercase['O']
subtext6 = Affine_Dec(subtext6,key)

# MERGE SUBTEXTS

plainText6 = ""

for i in range(len(subtext1)):
    plainText6 += subtext1[i]
    if i < len(subtext2):
        plainText6 += subtext2[i]
    if i < len(subtext3):
        plainText6 += subtext3[i]
    if i < len(subtext4):
        plainText6 += subtext4[i]
    if i < len(subtext5):
        plainText6 += subtext5[i]
    if i < len(subtext6):
        plainText6 += subtext6[i]
        
print(plainText6)