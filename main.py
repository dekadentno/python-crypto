#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5
import os

# https://pythonhosted.org/pycrypto/

def saveAs(filename, context):
    f = open(filename + '.txt', 'w')
    f.write(context)
    f.close()

def openFile(filename):
    f = open(filename, 'r')
    data = f.read()
    f.close()

    return data


def RSAkeys():
    private = RSA.generate(2048)
    public = private.publickey()

    saveAs('private_key', private.exportKey())
    saveAs('public_key', public.exportKey())

    print "Private key stored in private_key.txt."
    print "Public key stored in public_key.txt."

def AESkey():
    secretKey = os.urandom(32) # 256
    saveAs('secret_key', secretKey)

    print "Secret key stored in secret_key.txt."

def hashFile():
    dat = raw_input("Enter file name for hashing: (without .txt): ")
    data = openFile(dat + '.txt')

    print "File content: " + data

    h = SHA512.new(data)
    saveAs('SHA512', h.hexdigest())

    print "Hash of " + dat + ".txt stored in SHA512.txt."

def digitalSignature():
    # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Signature.PKCS1_v1_5-module.html

    dat = raw_input("Enter file name for a digital signature (without .txt): ")
    data = openFile(dat + '.txt')

    privateKey = RSA.importKey(open('private_key.txt').read())
    h = SHA512.new(data)
    signer = PKCS1_v1_5.new(privateKey)
    signature = signer.sign(h)

    saveAs("signature", signature)

    print "Digital signature stored in signature.txt."

def verifyDigSig():
    signature = openFile('signature.txt')

    dat = raw_input("Enter signed file name (without .txt): ")
    data = openFile(dat + '.txt')

    publicKey = RSA.importKey(open('public_key.txt').read())
    h = SHA512.new(data)
    verifier = PKCS1_v1_5.new(publicKey)

    if verifier.verify(h, signature):
        print "Digital signature is authentic."
    else:
        print "Digital signature is NOT authentic !"

def encryptRSA():
    dat = raw_input("Enter filename for encrypting: (without .txt): ")
    data = openFile(dat + '.txt')

    publicKey = RSA.importKey(open('public_key.txt').read())

    emsg = publicKey.encrypt(data, 'x')[0]

    saveAs("encrypted_RSA", emsg)

    print "File " + dat + " is encrypted and stored in encrypted_RSA.txt."


def decryptRSA():
    data = openFile('encrypted_RSA.txt')

    privateKey = RSA.importKey(open('private_key.txt').read())

    dmsg = privateKey.decrypt(data)

    print "File encrypted_RSA.txt is decrypted. File content: "
    print dmsg

def encryptAES():
    # http://docs.python-guide.org/en/latest/scenarios/crypto/

    dat = raw_input("Enter filename for encrypting: (without .txt): ")
    data = openFile(dat + '.txt')

    secretKey = openFile("secret_key.txt")
    iv = Random.new().read(AES.block_size)

    encryption = AES.new(secretKey, AES.MODE_CFB, iv)
    msg = encryption.encrypt(data)

    saveAs("iv", iv)
    saveAs("encrypted_AES", msg)

    print "File " + dat + " is encrypted and stored in encrypted_AES.txt."

def decryptAES():
    data = openFile("encrypted_AES.txt")

    secretKey = openFile("secret_key.txt")
    iv = openFile("iv.txt")

    decryption = AES.new(secretKey, AES.MODE_CFB, iv)
    plain = decryption.decrypt(data)
    
    print "File encrypted_AES.txt is decrypted. File content: "
    print plain

def main():
    ans=True
    while ans:
        print ("""
        -------------------------------------
        1. Generate private and public key (RSA-2048)
        2. Generate secret key (AES-256)

        3. Get file hash (SHA512)

        4. Digital signature
        5. Digital signature verification

        6. RSA encrytion
        7. RSA decryption

        8. AES encryption
        9. AES decryption
        ------------------------------------
        0. Exit
        ------------------------------------

        """)

        ans=raw_input("$ ~ ")

        if ans=="1":
            RSAkeys()
        elif ans=="2":
            AESkey()
        elif ans=="3":
            hashFile()
        elif ans=="4":
            digitalSignature()
        elif ans=="5":
            verifyDigSig()
        elif ans=="6":
            encryptRSA()
        elif ans=="7":
            decryptRSA()
        elif ans=="8":
            encryptAES()
        elif ans=="9":
            decryptAES()
        elif ans=="0":
            print("\nBye")
            exit()
        elif ans !="":
            print("what?")

if __name__ == "__main__":
    main()