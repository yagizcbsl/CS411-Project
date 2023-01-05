import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b

API_URL = 'http://10.92.52.255:5000/'

stuID = 28229
stuIDB = 2014

IKey_Pr = 49794081060644222630983286457417577119786554931289187555364178615215564572008
IKey_Pub = Point(int("0x67e394a50d85ec1cf37c5f8d37b4449a5d6c8652e0c8bc3d8d3c208e91fc43bf",base=16),int("0x8d30254df8356f68b9cbb7dbf3bab5d8a6310d94b01f26111b45ee2db3fd27cb",base=16),E)

SPK_S_Pub = Point(int("0xbc0360774a6ae550633c37ddde5f38a0497a7a1af5f7a60bb532aaf28957344b",base=16),int("0x667bc03d5faafd1d9ad4c44507ec00871ae35a63d688732c44710918ca67e5e9",base=16),E)
SPK_Pr = 105931760754407563980286278594093796614083827551827905850481317635950514500275
SPK_Pub = Point(int("0xe966db937b67aa1fd0bd9570390a7b388849e3351ffe51d1002a8406f4069c61",base=16),int("0x3cd734cb1ebdf6f7249a85ae563187247cbf98bd6edca33dd9965be5352487f3",base=16),E)

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def Setup():
    E = Curve.get_curve('secp256k1')
    return E

def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1,n-1)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(1,n-2)
    R = k*P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    s = (sA*h + k) % n
    return h, s

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P - h*QA
    v = V.x % n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False


#server's Identitiy public key
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, E)

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    print(response.json())

############## The new functions of phase 2 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

#######################################################

def sessionKeyGen(OTK_A_Pr,EK_B_Pub):
    T = OTK_A_Pr * EK_B_Pub
    U =  T.x.to_bytes((T.x.bit_length()+7)//8,byteorder="big") + T.y.to_bytes((T.y.bit_length()+7)//8,byteorder="big") +  "ToBeOrNotToBe".encode()
    return SHA3_256.new(U)

def keyDerivationFunction(KDF_Key):
    K_ENC = SHA3_256.new(KDF_Key.digest() + b'YouTalkingToMe')
    K_HMAC = SHA3_256.new(KDF_Key.digest() + K_ENC.digest() + b'YouCannotHandleTheTruth')
    K_NEXT = SHA3_256.new(KDF_Key.digest() + K_HMAC.digest() + b'MayTheForceBeWithYou')
    
    return K_ENC, K_HMAC, K_NEXT
    
def HMACKeyGen(SPK_Pr,SPK_Pub_Server):
    T = SPK_Pr * SPK_Pub_Server
    U = "CuriosityIsTheHMACKeyToCreativity".encode() + T.y.to_bytes((T.y.bit_length()+7)//8,byteorder="big") + T.x.to_bytes((T.x.bit_length()+7)//8,byteorder="big")
    return SHA3_256.new().update(U).digest()

def SignatureGeneration(message,IKey_Pr):
    k = Random.new().read(int(math.log(n,2)))
    k = int.from_bytes(k, byteorder='big') % n      
    R = k*P  
    r = R.x % n  
    conta = r.to_bytes((r.bit_length()+7)//8,byteorder="big") + message.to_bytes((message.bit_length()+7)//8,byteorder="big")
    hasher = SHA3_256.new()
    hasher.update(conta)
    h = int(hasher.hexdigest(),base=16) % n
    s = (k + IKey_Pr*h) % n
    return h,s

hO,sO = SignatureGeneration(stuID,IKey_Pr)
ResetOTK(hO,sO)

HMAC_Key = HMACKeyGen(SPK_Pr,SPK_S_Pub)
# # print(HMAC_Key)

OTKS = []
HMACIS = []

for i in range(10):
    OTK_Pr, OTK_Pub = KeyGen(E)
    concatenated =  OTK_Pub.x.to_bytes((OTK_Pub.x.bit_length()+7)//8,byteorder="big") + OTK_Pub.y.to_bytes((OTK_Pub.y.bit_length()+7)//8,byteorder="big")
    HMACI = HMAC.new(key=HMAC_Key,msg=concatenated,digestmod=SHA256).hexdigest()
    OTKReg(i,OTK_Pub.x,OTK_Pub.y,HMACI)
    OTKS.append((OTK_Pr,OTK_Pub))
    HMACIS.append(HMACI)

h,s = SignatureGeneration(stuID, IKey_Pr)
PseudoSendMsg(h,s)

ks = None
knext = None

for i in range(5):
    message = ReqMsg(h,s)
    #print(message)
    IDB = message[0]
    otkID = message[1]
    msgID = message[2]
    msg = message[3].to_bytes((message[3].bit_length() +7)//8, byteorder = 'big')
    nonce = msg[:8]
    MAC = msg[len(msg)-32:]
    ciphertext = msg[8:len(msg)-32]
    msg_nonce = msg[:len(msg)-32]
    msg_wo_nonce = msg[8:]
    EK_B_Pub = Point(int(message[4]),int(message[5]),E)
    OTK_A_Pr = OTKS[otkID][0]
    
    if i == 0:
        ks = sessionKeyGen(OTK_A_Pr,EK_B_Pub)
    else:
        ks = knext
    K_ENC, K_HMAC, knext = keyDerivationFunction(ks)
    
    hmac = HMAC.new(key=K_HMAC.digest(), msg=ciphertext, digestmod=SHA256).digest()
    
    if(hmac == MAC):
        print("HMAC verified")
        plaintext = AES.new(K_ENC.digest(), AES.MODE_CTR, nonce = msg_nonce[0:8]).decrypt(msg_wo_nonce)
        #plaintext = cipher.decrypt(msg_wo_nonce)
        plaintext2 = plaintext.decode('latin1')
        print("Decrypted message:", plaintext2)
        Checker(stuID, stuIDB, msgID, plaintext2)
            
    else: 
        print("HMAC not verified")
        Checker(stuID, stuIDB, msgID, 'INVALIDHMAC')
            

    
    
    

