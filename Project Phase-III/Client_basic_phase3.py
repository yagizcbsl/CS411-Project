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
import binascii
import os

API_URL = 'http://10.92.52.255:5000/'

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b

stuID = 28229
stuIDB = 29425

# IKey_Pr = 113359040262378011876979282979269298605265302723663430739085469103263950939267
# IKey_Pub = Point(int("0xd55018dd539f2f7e089cafcd37a8cb0a8ac9efd7cdac6d263c0fd11bded38df1",base=16),int("0xa48ee99fdf1afa837905224bec9d9283c545d9427b248541da32527e20a47ba5",base=16),E)

# SPK_Pr = 25777555511670854268982747702448570072084603082464838247541202388132067723990
# SPK_Pub = Point(int("0x2743edb2a487d13edefc6df7930f730d444a7f15d5317ad960edcc7eecfeaca5",base=16),int("0x33ac680fa32904d43e9f7a9938adb53cb8f88d49bd238108afb99b27e9bdce9f",base = 16),E)
# SPK_h = 18336420386507990120885529281772835950614099897813848735430773108579957236079
# SPK_s = 98519982661898934415885465966910813994081601479009468940052328733161983709814
# SPK_S_Pub = Point(85040781858568445399879179922879835942032506645887434621361669108644661638219,46354559534391251764410704735456214670494836161052287022185178295305851364841,E)


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
    global E
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
#print("In signature generation I fixed the random variable to 1748178 so that you can re-generate if you want")
def IKRegReq(h,s,x,y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(h,s,x,y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if(response.ok == False):
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID': stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    #print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    #print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    print(response.json())

def PseudoSendMsgPH3(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

def ReqMsg(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["MSGID"]

def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA': stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
    print(response.json())
    
    
def SendMsg(idA, idB, otkID, msgid, msg, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    
        
def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0

def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']


#######################################################################

def sessionKeyGen(OTK_A_Pr,EK_B_Pub):
    T = OTK_A_Pr * EK_B_Pub
    U =  T.x.to_bytes((T.x.bit_length()+7)//8,byteorder="big") + T.y.to_bytes((T.y.bit_length()+7)//8,byteorder="big") +  "ToBeOrNotToBe".encode()
    return SHA3_256.new().update(U).digest()

def keyDerivationFunction(KDF_Key):
    enc = KDF_Key + "YouTalkingToMe".encode()
    K_ENC = SHA3_256.new().update(enc).digest()
    
    hmac = KDF_Key + K_ENC + "YouCannotHandleTheTruth".encode()
    K_HMAC = SHA3_256.new().update(hmac).digest()
    
    nxt = hmac = K_ENC + K_HMAC + "MayTheForceBeWithYou".encode()
    K_NEXT = SHA3_256.new().update(nxt).digest()
    
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

def registerSPK(IKey_Pub,IKey_Pr):
    # Key generation
    SPK_Pr , SPK_Pub = KeyGen(E)
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

def registerOTKS(SPK_Pr,SPK_S_Pub):
    HMAC_Key = HMACKeyGen(SPK_Pr,SPK_S_Pub)
    print("HMAC_key is generated:",HMAC_Key)

    OTKS = []
    HMACIS = []

    for i in range(10):
        OTK_Pr, OTK_Pub = KeyGen(E)
        concatenated =  OTK_Pub.x.to_bytes((OTK_Pub.x.bit_length()+7)//8,byteorder="big") + OTK_Pub.y.to_bytes((OTK_Pub.y.bit_length()+7)//8,byteorder="big")
        HMACI = HMAC.new(key=HMAC_Key,msg=concatenated,digestmod=SHA256).hexdigest()
        OTKReg(i,OTK_Pub.x,OTK_Pub.y,HMACI)
        # print(i+1,"th key is generated")
        # print("Private OTK:",OTK_Pr)
        # print("Public OTK.x:",OTK_Pub.x)
        # print("Public OTK.y:",OTK_Pub.y)
        OTKS.append(OTK_Pr)
        
        HMACIS.append(HMACI)
        #print()
    #print(OTKS)
    return OTKS, HMACIS



#!!! IK !!!
# IKey_Pr, IKey_Pub = KeyGen(E)
# h,s = SignGen(stuID.to_bytes((stuID.bit_length()+7)//8,byteorder="big"),E,IKey_Pr)
# h,s = SignatureGeneration(stuID,IKey_Pr)
# print(SignatureVerification(stuID,s,h,IKey_Pub))
# IKRegReq(h,s,IKey_Pub.x,IKey_Pub.y)
# print(IKey_Pr,IKey_Pub)




# IKey_Pr = 49794081060644222630983286457417577119786554931289187555364178615215564572008
# IKey_Pub = Point(int("0x67e394a50d85ec1cf37c5f8d37b4449a5d6c8652e0c8bc3d8d3c208e91fc43bf",base=16),int("0x8d30254df8356f68b9cbb7dbf3bab5d8a6310d94b01f26111b45ee2db3fd27cb",base=16),E)
# code = 990997
# IKRegVerify(code)
# rcode = 953088

# ResetIK(rcode)


# # !!! SPK !!!
# SPK_S_Pub, SPK_Pr, SPK_Pub = registerSPK(IKey_Pub,IKey_Pr)
# print(SPK_S_Pub)
# print(SPK_Pr)
# print(SPK_Pub)


IKey_Pr = 49794081060644222630983286457417577119786554931289187555364178615215564572008
IKey_Pub = Point(int("0x67e394a50d85ec1cf37c5f8d37b4449a5d6c8652e0c8bc3d8d3c208e91fc43bf",base=16),int("0x8d30254df8356f68b9cbb7dbf3bab5d8a6310d94b01f26111b45ee2db3fd27cb",base=16),E)
SPK_S_Pub = Point(int("0xbc0360774a6ae550633c37ddde5f38a0497a7a1af5f7a60bb532aaf28957344b",base=16),int("0x667bc03d5faafd1d9ad4c44507ec00871ae35a63d688732c44710918ca67e5e9",base=16),E)
SPK_Pr = 105931760754407563980286278594093796614083827551827905850481317635950514500275
SPK_Pub = Point(int("0xe966db937b67aa1fd0bd9570390a7b388849e3351ffe51d1002a8406f4069c61",base=16),int("0x3cd734cb1ebdf6f7249a85ae563187247cbf98bd6edca33dd9965be5352487f3",base=16),E)


hO,sO = SignatureGeneration(stuID,IKey_Pr)
ResetOTK(hO,sO)

HMAC_Key = HMACKeyGen(SPK_Pr,SPK_S_Pub)
# # print(HMAC_Key)

#OTKS = [75370411700846156637918389016773068496844801667837297522017451420706352597768, 60813094576311443872452582992016807929604644313976925282064533072215604650046, 36967088079100240798877938721460365518790856577695178466358909564239407645530, 85431183904332266918385332150414577652194944485742702787564961481002339248569, 114819859624294859694241665966898764893395172994534644688242820758398700068701, 94405447239398651545216764436294865628139163565212705943015678900764414317093, 2450211262406071921512792832198798137486457682013722680338229663150859514506, 573183583218758841943715331560437263390106834027879215099993628530933903963, 24115438157639564836416879612425773730125782608507033040882532481939828253102, 36116044551209216875280888417641931121213882186435354594611746543176225307292]
#HMACIS = []

OTKS,HMACIS = registerOTKS(SPK_Pr,SPK_S_Pub)

h,s = SignatureGeneration(stuID, IKey_Pr)
PseudoSendMsgPH3(h,s)

num_msg,rem_otk, status_msg = Status(stuID,h,s)

ks = None
knext = None

msg_block = {}

print("-------------------------------------------------------------")

for i in range(num_msg):
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
    OTK_A_Pr = OTKS[otkID]
    
    if i == 0:
        ks = sessionKeyGen(OTK_A_Pr,EK_B_Pub)
    else:
        ks = knext
    K_ENC, K_HMAC, knext = keyDerivationFunction(ks)
    
    hmac = HMAC.new(key=K_HMAC, msg=ciphertext, digestmod=SHA256).digest()
    
    if(hmac == MAC):
        print("HMAC verified")
        plaintext = AES.new(K_ENC, AES.MODE_CTR, nonce = msg_nonce[0:8]).decrypt(ciphertext)
        #plaintext = cipher.decrypt(msg_wo_nonce)
        plaintext2 = plaintext.decode('utf-8',errors= 'ignore')
        #print("Decrypted message:", plaintext2)
        Checker(stuID, IDB, msgID, plaintext2)

        msg_block[msgID] = plaintext2
    else: 
        print("HMAC not verified")
        Checker(stuID, IDB, msgID, 'INVALIDHMAC')
    
    
    rem_msg,rem_otk, status_msg = Status(stuID,h,s)
    if rem_otk == 1:
        print("You have only 1 OTK left. Please register new OTKs")
        #registerOTKS(SPK_Pr, SPK_S_Pub)
    print("-------------------------------------------------------------")



# h,s = SignatureGeneration(26045,IKey_Pr)
# reqOTKB(stuID,26045,h,s)

print("Requesting the deleted messages: ")

h,s = SignatureGeneration(stuID,IKey_Pr)
deleted = ReqDelMsg(h,s)

print("These messages are deleted: ")
if len(deleted) > 1:
    for i in deleted:
        print("Message:", i , msg_block[i])

print()
print()

for i in msg_block:
    print("Message:", i , msg_block[i])


print("-------------------------------------------------------------")    

stuIDB = 29425  

stuid_byte = stuID.to_bytes(length=stuID.bit_length()+7//8, byteorder= 'big')


print("Now I want to send messages to my friend. Her id is", stuIDB,".")
print("Signing The stuIDB of party B with my private IK")

# msg_block = [
#     "Thou shalt not steal",
#     "I don't care even if it is Queen of England, You come to me, You tell me, You tell me everthing!!",
#     "Siuuu",
#     "The more you care, the more you have to lose",
#     "For Frodo",
#     "Close your heart to it, come then",
#     "If I'm to choose between one evil and another, then I prefer not to choose at all.",
#     "Hey, What is your name?",
#     "Ezekielll"
# ]
 

for msgID in msg_block:

    h,s = SignatureGeneration(stuIDB,IKey_Pr) 

    keyid, otkx, otky = reqOTKB(stuID, stuIDB, h,s)

    #OTK_Pr, OTK_A_Pub = KeyGen(E)
    OTK_A_Pub = Point(otkx,otky,E)

    Ks = None
    Knext = None

    ek_pr, ek_pub =  KeyGen(E)

    if Ks == None:
        Ks = sessionKeyGen(ek_pr,OTK_A_Pub)
    else:
        Ks = Knext
    Kenc , Khmac , Knext =  keyDerivationFunction(Ks)

    ciphertext = msg_block[msgID]

    send_nonce = os.urandom(8)

    ciphertext = ciphertext.encode()

    #print(ciphertext)

    ciphertext = AES.new(Kenc, AES.MODE_CTR, nonce = send_nonce).encrypt(ciphertext)

    hmac = HMAC.new(key=Khmac, msg=ciphertext, digestmod=SHA256).digest()

    encrypted_msg = send_nonce + ciphertext + hmac

    encrypted_msg = int.from_bytes(encrypted_msg, byteorder= 'big')

    SendMsg(stuID,stuIDB,keyid,msgID,encrypted_msg,ek_pub.x,ek_pub.y)

    h,s = SignatureGeneration(stuID,IKey_Pr)
    

print("Checking the status of the inbox ...")
hs, ss = SignatureGeneration(stuID,IKey_Pr)
num_msg,rem_otk, status_msg = Status(stuID,hs,ss)
if rem_otk == 1:
    print("You have only 1 OTK left. Please register new OTKs")
    registerOTKS(SPK_Pr, SPK_S_Pub)



