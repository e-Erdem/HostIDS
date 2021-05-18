# -*- coding: utf-8 -*-
"""
Created on Tue May 11 23:49:28 2021

@author: Efe
"""

# -*- coding: utf-8 -*-
"""
Created on Tue Apr 20 16:48:21 2021

@author: Efe
"""

import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from base64 import b64encode, b64decode
import json
import os
 
def encrypt(plaintxt, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)
    #print(salt)
    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    
    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plaintxt, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    
    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted
    
def scanner(foldername):
    Dict = {}
    password = input("Password: ")
    os.chdir('C:/Users/Efe/Desktop/'+foldername)
    arr = os.listdir('C:/Users/Efe/Desktop/'+foldername)
    for i in range(len(arr)):
        with open(arr[i],"rb") as f:
            bytes = f.read() # read entire file as bytes
            readable_hash = hashlib.sha256(bytes).hexdigest();
            f.close()
            encrypted = encrypt(readable_hash, password)
            a=str(i)
            json.dump(encrypted, open("C:/Users/Efe/Desktop/Hashes/"+a+".txt",'w'))
            Dict[i] = arr[i]
    json.dump(Dict, open("C:/Users/Efe/Desktop/Hashes/hello.txt",'w'))       
              
def detection(password):
    Dict = {}
    dicthello1 = json.load(open("C:/Users/Efe/Desktop/Hashes/hello.txt"))
    for i in range(len(dicthello1)):
        filename = dicthello1[str(i)]    
        dhello = json.load(open("C:/Users/Efe/Desktop/Hashes/"+str(i)+".txt"))
        decrypted = decrypt(dhello, password)  
        decryptedmes = bytes.decode(decrypted)
        Dict[filename] = decryptedmes
    return Dict

def readhash(foldername):
    Dict = {}
    #foldername = input("Please enter the directory Name: ")
    os.chdir('C:/Users/Efe/Desktop/'+foldername)
    arr = os.listdir('C:/Users/Efe/Desktop/'+foldername)
    for i in range(len(arr)):
        with open(arr[i],"rb") as f:
            filename = arr[i]
            bytes = f.read() # read entire file as bytes
            readable_hash = hashlib.sha256(bytes).hexdigest();
            f.close()
            Dict[filename] = readable_hash
    return Dict
    
print("(1) SCAN")
print("(2) DETECT")
print("(3) EXIT")
i = int(input(""))
while(i!=3):
    if(i==1):
        foldername = input("Please enter the directory Name: ")
        scanner(foldername);
    elif(i==2):
        foldername = input("Please enter the directory Name: ")
        password = input("Password: ")
        arr = os.listdir('C:/Users/Efe/Desktop/'+foldername)
        for i in range(len(arr)):
           if(detection(password)[str(arr[i])] == readhash(foldername)[str(arr[i])]):
               print(arr[i]+" is SAFE")
           else:
               print(arr[i]+" is MALICIOUS !!")
    print("(1) SCAN")
    print("(2) DETECT")
    print("(3) EXIT")
    i = int(input(""))    
        
    
    

    