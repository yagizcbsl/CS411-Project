import math
import time
import random as rnd
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


API_URL = 'http://10.92.55.4:5000'

stuID = 28229

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b

#Server's Identitiy public key
#IKey_Ser = IKeyPub(int("ce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d",base=16),int("13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093",base=16))
IKey_Ser = Point(int("0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d",base=16),int("0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093",base=16),E)
# Use the values in the project description document to form the server's IK as a point on the EC. Note that the values should be in decimal.

def KeyGeneration():
    S = Random.new().read(int(math.log(n,2)))
    S = int.from_bytes(S, byteorder='big') % n
    Q = S*P
    return S,Q

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

def SignatureVerification(m,s,h,IKey_Pub):
    V = s*P - h*IKey_Pub
    v = V.x % n
    conta = v.to_bytes((v.bit_length()+7)//8,byteorder="big") + m.to_bytes((m.bit_length()+7)//8,byteorder="big")
    hasher = SHA3_256.new()
    hasher.update(conta)
    hh = int(hasher.hexdigest(),base=16) % n
    if hh == h:
        return True
    return False

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)	
    if((response.ok) == False): print(response.json())
    

IKey_Pr = 44661277310780247524718275969077815626218888315083606580828598921329380822817
IKey_Pub = Point(0xa4b8e8aeaefe660d218c985b9285c1aa4b1b0a9e9717a0487dfb3bd46083f291,0x21ad20ea0d54b1316ae1efccfaa1f9358bc6023bc8d16ddf5f196f10fc545df2,E)

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
        f.close()
        
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
    if((response.ok) == False): print(response.json())
    

# Functions for much clearer look - I implemented these since I think it might be useful for the next step of the project
# so please consider, commented part at the bottom as the "functional part" of the phase 1.
 
def registeringIKtoServer():
    # Key Generation  
    IKey_Pr , IKey_Pub = KeyGeneration()
    print("Identity key is created")
    
    # Signing the student ID with IKey
    h,s = SignatureGeneration(stuID,IKey_Pr)
    print(stuID,"is signed with IKey of the user")
    
    if SignatureVerification(stuID,s,h,IKey_Pub):
        print("Signature has been checked and it is correct")
        # Sending signature of student ID, public key of IK, and student ID to the server in the given format
        IKRegReq(h,s,IKey_Pub.x,IKey_Pub.y)
    else:
        print("Signature has not been verified, check your work!")
    
    return IKey_Pr , IKey_Pub

def verifyIK(code):
    IKRegVerify(code)
    
def resetIK(rcode):
    ResetIK(rcode)    

def registerSPK(IKey_Pub,IKey_Pr):
    # Key generation
    SPK_Pr , SPK_Pub = KeyGeneration()
    print("Signed Pre-Key is created!")
    
    print("Private SPK:",SPK_Pr)
    print("Public SPK.x: ",SPK_Pub.x)
    print("Public SPK.y: ",SPK_Pub.y)
    
    SPKx , SPKy = SPK_Pub.x , SPK_Pub.y
    
    # Concatenation of SPK.x and SPK.y (SPK.x || SPK.y)
    concatenated_SPK = SPKx.to_bytes((SPKx.bit_length()+7)//8,byteorder="big") + SPKy.to_bytes((SPKy.bit_length()+7)//8,byteorder="big")
    concatenated_SPK = int.from_bytes(concatenated_SPK,byteorder="big")
    print("Concatenated SPK is generated and converted into integer:",concatenated_SPK)

    # Creation the signature of concatenated SPK signed with IKey_Pr
    SPK_h, SPK_s = SignatureGeneration(concatenated_SPK,IKey_Pr)
    if SignatureVerification(concatenated_SPK,SPK_s,SPK_h,IKey_Pub):
        print("Signature is created and verified")
        server_res = SPKReg(SPK_h,SPK_s,SPKx,SPKy)
        SPK_S_Pub = Point(server_res[0],server_res[1],E)
        return SPK_S_Pub, SPK_Pr, SPK_Pub
    else:
        print("Signature could not be verified! Check your work")

def resetSPK(IKey_Pr):
    h,s = SignatureGeneration(stuID,IKey_Pr)
    ResetSPK(h,s)
    
def HMACKeyGen(SPK_Pr,SPK_Pub_Server):
    T = SPK_Pr * SPK_Pub_Server
    U = "CuriosityIsTheHMACKeyToCreativity".encode() + T.y.to_bytes((T.y.bit_length()+7)//8,byteorder="big") + T.x.to_bytes((T.x.bit_length()+7)//8,byteorder="big")
    return SHA3_256.new().update(U).digest()

def registerOTKS(SPK_Pr,SPK_S_Pub):
    HMAC_Key = HMACKeyGen(SPK_Pr,SPK_S_Pub)
    print("HMAC_key is generated:",HMAC_Key)

    OTKS = []
    HMACIS = []

    for i in range(10):
        OTK_Pr, OTK_Pub = KeyGeneration()
        concatenated =  OTK_Pub.x.to_bytes((OTK_Pub.x.bit_length()+7)//8,byteorder="big") + OTK_Pub.y.to_bytes((OTK_Pub.y.bit_length()+7)//8,byteorder="big")
        HMACI = HMAC.new(key=HMAC_Key,msg=concatenated,digestmod=SHA256).hexdigest()
        OTKReg(i,OTK_Pub.x,OTK_Pub.y,HMACI)
        print(i+1,"th key is generated")
        print("Private OTK:",OTK_Pr)
        print("Public OTK.x:",OTK_Pub.x)
        print("Public OTK.y:",OTK_Pub.y)
        OTKS.append((OTK_Pr,OTK_Pub.x,OTK_Pub.y))
        HMACIS.append(HMACI)
        print()
    return OTKS, HMACIS

    

# # Key Generation
# IKey_Pr , IKey_Pub = KeyGeneration()

# # # Signing Message
# h,s = SignatureGeneration(stuID,IKey_Pr)

# # # Checking whether message signed succesfully or not
# print(SignatureVerification(stuID,s,h,IKey_Pub))

# # # Printing public and private key
# print(IKey_Pr,IKey_Pub)

# # # Sending message to the server
# IKRegReq(h,s,IKey_Pub.x,IKey_Pub.y)

# # Key obtained
# code = 151641

# # # # Verifying account
# IKRegVerify(code)

# # Resetting IK
# rcode = 536779
# ResetIK(rcode)


# # Signed Pre-Key (SPK)
# SPK_Pr , SPK_Pub = KeyGeneration()

# print(SPK_Pr,SPK_Pub)

# SPKx , SPKy = SPK_Pub.x , SPK_Pub.y
# concatenated_SPK = SPKx.to_bytes((SPKx.bit_length()+7)//8,byteorder="big") + SPKy.to_bytes((SPKy.bit_length()+7)//8,byteorder="big")
# concatenated_SPK = int.from_bytes(concatenated_SPK,byteorder="big")

# SPK_h, SPK_s = SignatureGeneration(concatenated_SPK,IKey_Pr)
# print(SignatureVerification(concatenated_SPK,SPK_s,SPK_h,IKey_Pub))
# SPK_S_Pub = SPKReg(SPK_h,SPK_s,SPKx,SPKy)
# print(SPK_S_Pub)


SPK_Pr = 25429662388130856894669260659088020478616535956178361204168665860343942620342
SPK_Pub = Point(int("0x56039552554e005e67202c48c6df5fbcb86e25b44f50b7827d78ef12192df74",base=16),int("0x8bc951a0e5f6c98dcefb3c88a642482aa28de828a1e535f161f6bc0a29a10319",base = 16),E)
SPK_h = 64521533101452177714359315443610335808341116918386214080235428626578690128898
SPK_s = 5219673971356277040138267026585764193505402167723150917310925409603460713471

#SPK_S_Pub = (56639757923349849611343281406087185169440496922691141801327518124754702485302, 60393615797913336386435708272243523005927060424158141789698645816131859206963, 2004815621613086637054156671164926606881482163725952634282766566742357541143, 92501045717019568033017955368148119256648394943534684117874681618917739411346)
SPK_S_Pub = Point(56639757923349849611343281406087185169440496922691141801327518124754702485302,60393615797913336386435708272243523005927060424158141789698645816131859206963,E)

#  # Resetting SPK and OTKS
# h,s = SignatureGeneration(stuID,IKey_Pr)
# ResetSPK(h,s)

# One-time Pre-Key (OTK)

# Generating HMAC Key

# HMAC_Key = HMACKeyGen(SPK_Pr,SPK_S_Pub)
# print(HMAC_Key)

# OTKS = []
# HMACIS = []

# for i in range(10):
#     OTK_Pr, OTK_Pub = KeyGeneration()
#     concatenated =  OTK_Pub.x.to_bytes((OTK_Pub.x.bit_length()+7)//8,byteorder="big") + OTK_Pub.y.to_bytes((OTK_Pub.y.bit_length()+7)//8,byteorder="big")
#     HMACI = HMAC.new(key=HMAC_Key,msg=concatenated,digestmod=SHA256).hexdigest()
#     OTKReg(i,OTK_Pub.x,OTK_Pub.y,HMACI)
#     OTKS.append((OTK_Pr,OTK_Pub))
#     HMACIS.append(HMACI)
    
# print(OTKS)
# print(HMACIS)
    
    