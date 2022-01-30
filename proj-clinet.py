
import os
import random
import socket
import sys

import rsa
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from hashlib import sha512



publickey_server="client/publickey_server.txt"
f=open(publickey_server,"r+")
line=f.readline()
line=line.split("/")
n=int(line[0])
e=int(line[1])
f.close()



    





publickey_server=rsa.PublicKey(n,e)
publicKey_client, privateKey_client = rsa.newkeys(512)

sessionkey=""


n=publicKey_client.n
e=publicKey_client.e



def check_integriy(sign,mess):
    msg = mess
    keyPair=publickey_server
    hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
    hashFromSignature = pow(sign, keyPair.e, keyPair.n)
    return hash == hashFromSignature




blp={"Top_secret":10,"secret":8,"confidential":6,"unclassified":0}
biba={"very_trusted":10,"trusted":7,"unclassified":0}



message="sessionkey/"+str(n)+"/"+str(e)
message = rsa.encrypt(message.encode(),publickey_server)
print("inter ip")
ip=input()
cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cs.connect((ip, 1212))
print("client is ready now\n")
cs.send(message)




senmess= cs.recv(1024)
hash_pri=int(cs.recv(1024).decode())
senmess = rsa.decrypt(senmess, privateKey_client)
# senmess= rsa.decrypt(senmess, publickey_server).decode()
sessionkey=senmess
flag=check_integriy(hash_pri,sessionkey)
if(flag==False):
    print("conection Wrong")
    sys.exit()

Ra=random.randint(0,1000000)
message=Ra
fernet = Fernet(sessionkey)
message = fernet.encrypt(str(message).encode())
cs.send(message)
senmess = cs.recv(1024)
message = str(fernet.decrypt(senmess).decode())
message=message.split("/")
Rb=int(message[1])
Ra_send=int(message[0])
if(Ra!=Ra_send):
    print("conection Wrong")
    sys.exit()
message=str(Rb)+"/"
message = fernet.encrypt(message.encode())
cs.send(message)















            
def decode(msg):
    return fernet.decrypt(msg).decode()

def encode(msg):
    return fernet.encrypt(str(msg).encode())
    
    

    

    




while True:

    print("for sign up number 1 \n for sign in number 2")
    num = int(input())
    if(num == 1):
        print("please inter name")
        name = input()
        print("please inter family name")
        familyname = input()
        print("please inter username")
        username = input()
        print("please inter password")
        password = input()
        message="adduser/"+name+"/"+familyname+"/"+username+"/"+password+"/"
        cs.send(encode(message))
        l = decode(cs.recv(1024))
        l=l.split(",")
        if(l[0]=="failed"):
            print("process failed "+l[1])
        else:
            print("process done sucessfuly")
    if(num==2):
        print("please inter username \n")
        username = input()
        print("please inter password")
        password = input()
        message="login/"+username+"/"+password
        cs.send(encode(message))
        l = decode(cs.recv(1024))
        l=l.split("/")
        if(l[0]=="failed"):        
            print("login failed")
        elif(l[0]=="accept"):
            print("login accept")
            num=0
            while(num!=10):
                print("to create group number 1\nto add user to your group num2\nto change access control users in group num3 \n for send or recive message num4\nto finish inter 10")
                num=int(input())
                if(num==1):
                    print("inter name of group")
                    name_group=input()
                    print("please inter level of blp of group")
                    print(blp)
                    blplevel=input()
                    print("please inter biba level of group ")
                    print(biba)
                    bibalevel=input()
                    message="create_group/"+name_group+"/"+str(blp[blplevel])+"/"+str(biba[bibalevel])                
                    cs.send(encode(message))
                    l = decode(cs.recv(1024))
                    l=l.split("/")
                    if(l[0]=="accept"):
                        print("group created")
                    else:
                        print("cant create this group")
                elif(num==2):
                    print("enter name of your group")
                    name_group=input()
                    print("inter username of person you want to add")
                    user=input()
                    print("inter type of blp permission")
                    print(blp)
                    blpperm=input()
                    print("inter type of biba permission")
                    print(biba)
                    bibaperm=input()
                    
                    message="adduser/"+name_group+"/"+user+"/"+str(blp[blpperm])+"/"+str(biba[bibaperm])
                    cs.send(encode(message))
                    l = decode(cs.recv(1024))
                    l=l.split("/")
                    if(l[0]=="accept"):
                        print("user added")
                    else:
                        print("user not add")
                elif(num==3):
                    print("change permission")
                    print("enter name of your group")
                    name_group=input()
                    print("inter username of person you want to change")
                    user=input()
                    print("inter type of blp permission")
                    print(blp)
                    blpperm=input()
                    print("inter type of biba permission")
                    print(biba)
                    bibaperm=input()
                    message="changeperm/"+name_group+"/"+user+"/"+str(blp[blpperm])+"/"+str(biba[bibaperm])
                    cs.send(encode(message))
                    l = decode(cs.recv(1024))
                    l=l.split("/")
                    if(l[0]=="accept"):
                        print("user perm changes")
                    else:
                        print("failed operation")
                elif(num==4):
                    print("inter name of group")
                    gropname=input()
                    print("inter username of group (who is owner of group)")
                    ownergroup=input()
                    message="message/"+gropname+"/"+ownergroup
                    cs.send(encode(message))
                    l = decode(cs.recv(1024))
                    l=l.split("/")
                    if(l[0]!="accept"):
                        print("not find group")
                        continue
                    else:
                        while(True):
                            print("find group\n")
                            print("to send message num 1 \n to recive num 2\n to get out inter num3\nto delete message num 4")
                            num=int(input())
                            if(num==1):
                                print("inter your message")
                                string=input()
                                message="sendmessage/"+string
                                cs.send(encode(message))
                                l = decode(cs.recv(1024))
                                l=l.split("/")
                                if(l[0]!="accept"):
                                    print("failed")
                                else:
                                    print("done")
                            elif(num==2):
                                message="getmessage/"
                                cs.send(encode(message))
                                l = decode(cs.recv(4096))
                                l=l.split("/")
                                if(l[0]!="accept"):
                                    print("failed")
                                else:
                                    print("the message is:")
                                    print(l[1])
                            elif(num==3):
                                mess="finish/"
                                cs.send(encode(mess))
                                break
                            elif(num==4):
                                message="mymess/"
                                cs.send(encode(message))
                                l = decode(cs.recv(4096))
                                print("which one you want to delete")
                                print(str(l))
                                number=int(input())
                                message="delete/"+str(number)
                                cs.send(encode(message))
                                l = decode(cs.recv(4096))
                                l=l.split("/")
                                if(l[0]!="accept"):
                                    print("delete message failed")
                                else:
                                    print("delete accept")
                                
                                
                                
                elif(num==10):           
                    message="finish/"
                    cs.send(encode(message))
                    
                        
                          
                
            
            
            

        
        


