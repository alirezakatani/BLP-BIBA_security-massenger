

from __future__ import barry_as_FLUFL
from cmath import log
import socket
import os
import sys
import random
from tokenize import group
from attr import define
import hashlib
from cryptography.fernet import Fernet
import rsa
from hashlib import sha512
import time
from Crypto.PublicKey import RSA
from datetime import datetime




# RSA sign the message
logfilename="logfile.txt"

privatekey_server="privatekey_server.txt"

publickey_server="publickey_server.txt"


file_enc=b'FI_WHkR9AnynQeletCTYz76iZ-kLo99LpE-TCaaT8Uw='
key_file=Fernet(file_enc)







Score_uppercase=2
Score_downercase=2
Score_digit=2
Score_char=2
Score_need_toaccept=8


def decrypt_file(filename):
    try:
        f = key_file
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data).decode()
        os.remove(filename)
        
        f = open(filename, "w")
        f.write(decrypted_data)
        f.close()
        
        # return decrypted_data
    except Exception as e:
        print(e)
        open(filename,"ab")
        return ""


def encrypted_file(filename):
    try:
        f = key_file
        string=""
        file= open(filename, "r")
        for x in file:
            string+=x
        decr_con=string
        os.remove(filename)
        encrypted_data = f.encrypt(str(decr_con).encode())
        with open(filename, "wb") as file:
            file.write(encrypted_data)
        file.close()
    except Exception as e:
        print("eror encrypts"+str(e))



logfilename="logfile.txt"



def logging(message):
    try:
        decrypt_file(logfilename)
        f=open(logfilename,"a")
        format=str(datetime.now())+"/"+str(message)+"/"+"\n"
        f.write(format)
        f.close()
        encrypted_file(logfilename)
    except:
        print("eror in write log file")
    
        


f=open(publickey_server,"r+")
line=f.readline()
line=line.split("/")
n=int(line[0])
e=int(line[1])
publickey=rsa.PublicKey(n,e)
f.close()



decrypt_file(privatekey_server)
f=open(privatekey_server,"r+")
line=f.readline()
line=line.split("/")
n=int(line[0])
e=int(line[1])
d=int(line[2])
p=int(line[3])
q=int(line[4])
privatekey=rsa.PrivateKey(n,e,d,p,q)
encrypted_file(privatekey_server)


f.close()


def return_sign(mess):
    msg = mess
    hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
    signature = pow(hash,privatekey.d, privatekey.n)
    return signature













def check(senmess):
    upercase=min(sum(1 for c in senmess if c.isupper()),Score_uppercase)
    lowercase=min(sum(1 for c in senmess if c.islower()),Score_downercase)
    sign=0
    digit=0
    logging("check password user")
    for i in range(len(senmess)):
        if(senmess[i]=="!" or senmess[i]=="@" or senmess[i]=="#" or senmess[i]=="$" or senmess[i]=="%" or senmess[i]=="^" or senmess[i]=="&" or senmess[i]=="*"):
            sign+=1
        if(senmess[i].isdigit()):
            digit+=1
    sign=min(sign,Score_digit)
    digit=min(digit,Score_digit)
    score=sign+digit+lowercase+upercase+len(senmess[4])
    if(score>=Score_need_toaccept):
        return True
    return False


            


IP="127.0.0.1"

while(True):
    try:


        serverport = 1212
        serso = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("IP is"+IP)
        serso.bind((IP, serverport))
        serso.listen(10)
        path = ".\\"
        mainaddress = os.getcwd()
        print("server is ready now :)")  
        logging("set ip address with "+str(IP))
            

            
        conso, addr = serso.accept()
            



        # session key set
        publickey_client=""
        sessionkey=""


        senmess = conso.recv(1024)
        senmess = rsa.decrypt(senmess, privatekey).decode()
        senmess=senmess.split("/")
        fernet=None
        if(senmess[0]=="sessionkey"):
            logging("set session key")
            n=int(senmess[1])
            e=int(senmess[2])
            publickey_client=rsa.PublicKey(n,e)
            sessionkey= Fernet.generate_key()
            message=sessionkey
            fernet=Fernet(sessionkey)
            encmess_clinet1 = rsa.encrypt(message,publickey_client)
            hash_privatekey=return_sign(message)
            conso.send(encmess_clinet1)
            time.sleep(5)
            conso.send(str(hash_privatekey).encode())
            senmess = conso.recv(1024)
            message = fernet.decrypt(senmess).decode()
            Rb=random.randint(0,1000000)
            message=str(message)+"/"+str(Rb)
            encmessage = fernet.encrypt(str(message).encode())
            conso.send(encmessage)
            l = conso.recv(1024)
            message = fernet.decrypt(senmess).decode()
            message=message.split("/")
            Rb_send=int(Rb)
            if(Rb!=Rb_send):
                print("connection refused")
                logging("set session key failed for RB incorrect")
                continue
            
            
            
        def decode(msg):
            return fernet.decrypt(msg).decode()
        
        def encode(msg):
            return fernet.encrypt(str(msg).encode())

        
        
                
        while True:
    
            try:
                
                senmess = decode(conso.recv(1024))
                senmess=senmess.split("/")
                if(senmess[0]=="adduser"):
                    flag=True
                    try:
                        logging("adduser to system")
                        decrypt_file("usersub.txt")
                        f = open("usersub.txt", "r")
                        if(f!=None):
                            for x in f:
                                x=x.split("/")
                                if(x[2]==senmess[3]):
                                    flag=False
                                    senmess="failed,because of invlaid usename"
                                    break
                        if(check(senmess)==False):
                            flag=False
                            logging("adduser failed")
                            senmess="failed,because of invalid password,need to get score more then 20"
                        if(flag==True):

                            f = open("usersub.txt", "a")
                            passwd=str(hashlib.sha256(senmess[4].encode()).hexdigest())
                            format=str(senmess[1])+"/"+str(senmess[2])+"/"+str(senmess[3])+"/"+passwd+"/"+str(publickey_client.n)+"/"+str(publickey_client.e)+"/"+"\n"
                            f.write(str(format))
                            f.close()
                            logging("add user success with username"+str(senmess[2]))
                            senmess="done"
                        conso.send(encode(senmess))
                        
                    except Exception as e:
                        f = open("usersub.txt", "w+")
                        ex="failed process because of "+str(e)+" please try again"
                        print(ex)
                        conso.send(encode(ex))
                        logging("add user failed")
                    finally:
                        encrypted_file("usersub.txt")

                        
                elif(senmess[0]=="login"):
                        logging("login call")
                        flag=False
                        decrypt_file("usersub.txt")
                        try:
                            f = open("usersub.txt", "r")
                            passhash=hashlib.sha256(str(senmess[2]).encode()).hexdigest()
                            username=str(senmess[1])
                            if(f!=None):
                                for x in f:
                                    x=x.split("/")
                                    if(x[2]==str(senmess[1]) and passhash==x[3] ):
                                        flag=True
                                        logging("login successfuly happen with user name :"+str(username))
                                        senmess="accept/"
                                        break
                            
                        except Exception as e:   
                            print(str(e))
                            senmess+=str(e)+"/"
                        finally:
                            encrypted_file("usersub.txt")

                        if(flag==False):
                            senmess="failed/"
                            conso.send(encode(senmess))
                            logging("login failed")
                        if(flag==True):
                            conso.send(encode(senmess))
                            # senmess = decode(conso.recv(1024))
                            senmess="start/"
                            senmess=senmess.split("/")
                            message=""

                            while(str(senmess[0])!="finish"):
                                senmess = str(decode(conso.recv(1024)))
                                senmess=senmess.split("/")
                                message=""
                                if(senmess[0]=="create_group"):
                                    groupname=senmess[1]
                                    blpperm=senmess[2]
                                    bibaperm=senmess[3]
                                    user_create_group=username
                                    information=username+"/"+groupname+"/"+str(blpperm)+"/"+str(bibaperm)+"/"+"\n"
                                    filename=username+"_"+groupname+".txt"
                                    file_message=username+"_"+groupname+"_"+"message"+".txt"
                                    decrypt_file(filename)
                                    decrypt_file(file_message)
                                    try:
                                        f1=open(file_message,"w+")
                                        f2= open(filename,"w+")
                                        if(f1==None or f2==None):
                                            message="failed/"
                                        else:
                                            f2.write(str(information))
                                            f1.close()
                                            f2.close()
                                            message="accept/"
                                            logging("group created for username :"+str(username)+"/blpmode:"+str(blpperm)+"/bibamode"+str(bibaperm)+"/\n")
                                        conso.send(encode(message))
                                    except Exception as e:
                                        print(str(e))
                                        message+=str(e)+"/"
                                        logging("create group with username :"+str(username))
                                    finally:
                                        encrypted_file(filename)
                                        encrypted_file(file_message)
                                elif(senmess[0]=="adduser"):
                                    try:
                                        groupname=senmess[1]
                                        user_add=senmess[2]
                                        blpmode=senmess[3]
                                        bibamode=senmess[4]
                                        logging("adduser to group")
                                        filename=username+"_"+groupname+".txt"
                                        decrypt_file(filename)
                                        f = open(filename, "a")
                                        if(f==None):
                                            message="failed/"
                                            conso.send(encode(message))
                                            logging("failed add user to group")
                                        else:
                                            
                                                message="accept/"
                                                format=user_add+"/"+groupname+"/"+blpmode+"/"+bibamode+"/"+"\n"
                                                f.write(str(format))
                                                f.close()
                                                conso.send(encode(message))
                                                logging("add user to group success:/"+str(format))
                                    except:
                                        message="failed/"
                                        conso.send(encode(message))
                                    finally:
                                        encrypted_file(filename)
                                elif(senmess[0]=="changeperm"):
                                    try:
                                        logging("change permission of user")
                                        groupname=senmess[1]
                                        user_add=senmess[2]
                                        blpmode=senmess[3]
                                        bibamode=senmess[4]
                                        filename=username+"_"+groupname+".txt"
                                        decrypt_file(filename)
                                        a_file = open(filename, "r")
                                        try:

                                            if(f==None):
                                                message="failed/"
                                                conso.send(encode(message))
                                                logging("change permisson failed ,file doesnt exist filename:"+str(filename))
                                                # encrypted_file(filename)
                                            else:
                                                lines = a_file.readlines()
                                                a_file.close()
                                                format=user_add+"/"+groupname+"/"+blpmode+"/"+bibamode+"/"+"\n"
                                                logging("change permission accept info:"+str(format))
                                                new_file = open(filename, "w")
                                                for line in lines:
                                                    st=line.split("/")
                                                    if st[0]!=user_add:
                                                        new_file.write(line)
                                                    else:
                                                        new_file.write(format)

                                                    
                                                new_file.close()
                                        except:
                                            print(str(e))
                                            logging("change perm failed")
                                        finally:
                                            message="accept/"
                                            conso.send(encode(message))
                                            encrypted_file(filename)
                                    except:
                                        
                                        message="failed/"
                                        conso.send(encode(message))

                                elif(senmess[0]=="message"):
                                    try:
                                        logging("message section")
                                        groupname=senmess[1]
                                        ownergroup=senmess[2]
                                        blpperm=""
                                        bibaperm=""
                                        blpperm_ofgroup=""
                                        bibaperm_ofgroup="" 
                                        filename=ownergroup+"_"+groupname+".txt"
                                        if(not(os.path.isfile(filename))):
                                            raise OSError
                                        decrypt_file(filename)     
                                        f = open(filename, "r")
                                        line=f.readline().split("/")
                                        blpperm_ofgroup=int(line[2])
                                        bibaperm_ofgroup=int(line[3])
                                        if(x==None):
                                            mess="failed/"
                                            logging("reading group file failed ,filename"+str(filename))
                                            conso.send(encode(message))
                                            encrypted_file(filename)
                                            ""
                                            continue
                                        else:                           
                                            flag=False
                                            for x in f:
                                                x=x.split("/")
                                                if(x[0]==username):
                                                    blpperm=int(x[2])
                                                    bibaperm=int(x[3])
                                                    flag=True
                                                    logging("group find ,group name:"+str(groupname))
                                                    senmess="accept/"
                                                    break
                                            encrypted_file(filename)
                                            if(flag==False):
                                                senmess="failed/"
                                                logging("group not find ")
                                                conso.send(encode(senmess))
                                                continue
                                            else:
                                                conso.send(encode(senmess))
                                                mess ="start"
                                                file_message=ownergroup+"_"+groupname+"_"+"message"+".txt"
                                                # decrypt_file(file_message)
                                                
                                                try:
                                                    while(True):
                                                        mess =str(decode(conso.recv(1024)))
                                                        mess=mess.split("/")
                                                        if(mess[0]=="sendmessage"):
                                                            if(bibaperm>=bibaperm_ofgroup):
                                                                file_message=ownergroup+"_"+groupname+"_"+"message"+".txt"
                                                                decrypt_file(file_message)  #can be commented
                                                                f = open(file_message, "a")
                                                                if(f==None):
                                                                    message="failed/"
                                                                    conso.send(decode(message))
                                                                    logging("sending message failed ,username:"+str(username))
                                                                else:
                                                                    logging("sending message accept ,username:"+str(username))
                                                                    message="accept/"
                                                                    format=username+"/"+str(blpperm)+"/"+str(bibaperm)+"/"+mess[1]+"/"+"\n"
                                                                    f.write(str(format))
                                                                    f.close()
                                                                    conso.send(encode(message))
                                                                encrypted_file(file_message) #can be commented
                                                            else:
                                                                encrypted_file(file_message)#can be commented
                                                                message="failed/"
                                                                conso.send(encode(message))

                                                        elif(mess[0]=="getmessage"):
                                                            if(blpperm>=blpperm_ofgroup):
                                                                logging("recive  message accept ,username:"+str(username))
                                                                file_message=ownergroup+"_"+groupname+"_"+"message"+".txt"
                                                                decrypt_file(file_message) #can be commented
                                                                f = open(file_message, "r")
                                                                perm_mess=""
                                                                for x in f:
                                                                    mess=x.split("/")
                                                                    if(blpperm>=blpperm_ofgroup):
                                                                        perm_mess+=mess[3]+"\n"
                                                                message="accept/"+str(perm_mess)
                                                                conso.send(encode(message))
                                                                encrypted_file(file_message) #can be commented
                                                            else:
                                                                logging("recive message failed ,username:"+str(username))
                                                                encrypted_file(file_message)#can be commented
                                                                message="failed/"
                                                                conso.send(encode(message))
                                                        elif(mess[0]=="mymess"):
                                                            if(bibaperm>=bibaperm_ofgroup):
                                                                logging("showing personal message accept ,username:"+str(username))
                                                                file_message=ownergroup+"_"+groupname+"_"+"message"+".txt"
                                                                decrypt_file(file_message) #can be commented
                                                                f = open(file_message, "r")
                                                                perm_mess=""
                                                                number=0
                                                                allmessage=[]
                                                                for x in f:
                                                                    mess=x.split("/")
                                                                    if(blpperm>=blpperm_ofgroup and username==str(mess[0])):
                                                                        number+=1
                                                                        perm_mess+="num "+str(number)+"  "+str(mess[3])+"\n"
                                                                    allmessage.append(str(x))
                                                                message="accept/"+str(perm_mess)
                                                                conso.send(encode(message))
                                                                f.close()
                                                                l = decode(conso.recv(4096))
                                                                l=l.split("/")
                                                                newfile= open(file_message, "w+")
                                                                number=1
                                                                if(l[0]=="delete"):
                                                                    deleteitem=int(l[1])
                                                                    for x in allmessage:
                                                                        mess=x.split("/")
                                                                        if(username==str(mess[0]) and number!=deleteitem):
                                                                            newfile.write(x)
                                                                        elif(username!=str(mess[0])):
                                                                            newfile.write(x)
                                                                        number+=1
                                                                newfile.close()
                                                                encrypted_file(file_message) #can be commented
                                                                conso.send(encode("accept/"))
                                                            else:
                                                                logging("recive message failed ,username:"+str(username))
                                                                encrypted_file(file_message)#can be commented
                                                                message="failed/"
                                                                conso.send(encode(message))
                                                        elif(mess[0]=="finish"):
                                                            # encrypted_file(file_message) 
                                                            #if sentece 402,416,426,413 commented this must be decomment 
                                                            break
                                                except Exception as e:
                                                    print(str(e))
                                                    message+=str(e)
                                                    conso.send(encode(message))
                                                finally:
                                                    print()
                                                    # encrypted_file(file_message)
                                    except:
                                        message="failed/"
                                        conso.send(encode(message))
                                        

                                                

                                            
                                                
            except Exception as E:                                    
                print(str(E))
                conso.send(encode(str(E)))
                                            
                                                        
    except:                    
        print("request failed")
    finally:
        IP=IP.split(".")
        num=int(IP[3])+1
        IP=IP[0]+"."+IP[1]+"."+IP[2]+"."+str(num)
                                                
                                                        
                                                        

# encrypted_file(logfilename)                                                   
                                                
                                                
                                                
                                            

                                                
                                        
                                        

                                        

                                    

                                        

                                        
                            
                                

                            
                            
                        
  

                    
                    
                    


                    
                

                
                        

        
            
             
                  
                    


# def listfunction(path):
#     messerv = ""
#     arr = os.listdir(path)
#     size = 0
#     for file in arr:
#         path = os.getcwd()
#         path += "\\"+file
#         value = os.path.isdir(path)
#         size += os.path.getsize(path)
#         if(value == False):
#             messerv += str(file+"\n")
#         elif value is True:
#             messerv += str(">"+file+"\n")
#     messerv += "\n total size is"+str(size)
#     conso.send(messerv.encode())


# def downloadfile(senmess):
#     downport = random.randint(3000, 5000)
#     dosoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     dosoc.bind(("127.0.0.1", downport))
#     conso.send(str(downport).encode())
#     dosoc.listen(1)
#     doso, adddoc = dosoc.accept()
#     address = senmess[5:]
#     size = os.d(str(size).encode())
#     f = openpath.getsize(os.getcwd()+"\\"+address)
#     conso.sen(address, "rb")
#     l = f.read(size)
#     doso.send(l)
#     print("file is sending \n")
#     doso.close()
#     dosoc.close()


# conso, addr = serso.accept()


        
    # if(senmess == "HELP"):
    #     try:
    #         messerv = "HELP \n LIST \n DWLDfilePath \n PWD \n CD dirname"
    #         conso.send(messerv.encode())
    #         # conso.close()
    #     except Exception as e:
    #         print(e)
    #         messerv = str(e)
    #         conso.send(messerv.encode())
    # elif(senmess == "LIST"):
    #     try:
    #         listfunction(path)
    #         # conso.close()
    #     except Exception as e:
    #         print(str(e))
    #         messerv = str(e)
    #         conso.send(messerv.encode())
    # elif "DWLD" in senmess:
    #     try:
    #         downloadfile(senmess)
    #         # conso.close()
    #     except Exception as e:
    #         print(str(e)+"\n eror  in noexist file")
    #         messerv = str(e)+"\n eror  in noexist file"
    #         conso.send(messerv.encode())
    # elif(senmess == "PWD"):
    #     try:
    #         messerv = os.getcwd()

    #         conso.send(messerv.encode())
    #         # conso.close()

    #     except Exception as e:
    #         print(str(e)+"\n eroer in no exist directort ")
    #         messerv = str(e)+"\n eroer in no exist directort "
    #         conso.send(messerv.encode())
    # elif "CD" in senmess:
    #     try:
    #         os.chdir(senmess[3:])
    #         messerv = "done"
    #         conso.send(messerv.encode())
    #     except Exception as e:
    #         print(str(e)+"\n eror with open directory ")
    #         messerv = str(e)+"\n eroer in no exist directory "
    #         conso.send(messerv.encode())
    # else:
    #     print("we have not this command you entered")
    #     messerv = "we have not this command you entered"
    #     conso.send(messerv.encode())
# conso.close()