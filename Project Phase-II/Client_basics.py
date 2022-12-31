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

IKey_Pr = 44661277310780247524718275969077815626218888315083606580828598921329380822817
IKey_Pub = Point(0xa4b8e8aeaefe660d218c985b9285c1aa4b1b0a9e9717a0487dfb3bd46083f291,0x21ad20ea0d54b1316ae1efccfaa1f9358bc6023bc8d16ddf5f196f10fc545df2,E)
SPK_Pr = 25429662388130856894669260659088020478616535956178361204168665860343942620342
SPK_Pub = Point(int("0x56039552554e005e67202c48c6df5fbcb86e25b44f50b7827d78ef12192df74",base=16),int("0x8bc951a0e5f6c98dcefb3c88a642482aa28de828a1e535f161f6bc0a29a10319",base = 16),E)
SPK_h = 64521533101452177714359315443610335808341116918386214080235428626578690128898
SPK_s = 5219673971356277040138267026585764193505402167723150917310925409603460713471
SPK_S_Pub = Point(56639757923349849611343281406087185169440496922691141801327518124754702485302,60393615797913336386435708272243523005927060424158141789698645816131859206963,E)


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
    k = randint(1, n-2)
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
    return SHA3_256.new().update(U).digest()

def keyDerivationFunction(KDF_Key):
    enc = KDF_Key.to_bytes((KDF_Key.bit_length()+7)//8,byteorder="big") + "YouTalkingToMe".encode()
    K_ENC = SHA3_256.new().update(enc).digest()
    
    hmac = KDF_Key.to_bytes((KDF_Key.bit_length()+7)//8,byteorder="big") + K_ENC.to_bytes((K_ENC.bit_length()+7)//8,byteorder="big") + "YouCannotHandleTheTruth".encode()
    K_HMAC = SHA3_256.new().update(hmac).digest()
    
    nxt = hmac = K_ENC.to_bytes((K_ENC.bit_length()+7)//8,byteorder="big") + K_HMAC.to_bytes((K_HMAC.bit_length()+7)//8,byteorder="big") + "MayTheForceBeWithYou".encode()
    K_NEXT = SHA3_256.new().update(nxt).digest()
    
    return K_ENC, K_HMAC, K_NEXT
    
h,s = SignGen(stuID.to_bytes((stuID.bit_length()+7)//8,byteorder="big"),E,IKey_Pr)

PseudoSendMsg(h,s)
message = ReqMsg(h,s)
print(message)



