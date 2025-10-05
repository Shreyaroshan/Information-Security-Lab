
def addcipher_encrypt(str,key):
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr((ord(str[i])+key-65)%26+65)
        elif str[i].islower():
            ans+=chr((ord(str[i])-97+key)%26+65)
        else:
            ans+=str[i]
    return ans

def addcipher_decrypt(str,key):
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr((ord(str[i])-key-65)%26+97)
        elif str[i].islower():
            ans+=chr((ord(str[i])-97-key)%26+97)
        else:
            ans+=str[i]
    return ans

def mulcipher_encrypt(str,key):
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr(((ord(str[i])-65)*key)%26+65)
        elif str[i].islower():
            ans+=chr(((ord(str[i])-97)*key)%26+65)
        else:
            ans+=str[i]
    return ans

def mulcipher_decrypt(str,key):
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr(((ord(str[i])-65)*pow(key,-1,26))%26+97)
        elif str[i].islower():
            ans+=chr(((ord(str[i])-97)*pow(key,-1,26))%26+97)
        else:
            ans+=str[i]
    return ans

def affine_encrypt(str,k1,k2):
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr(((ord(str[i])-65)*k1+k2)%26+65)
        elif str[i].islower():
            ans+=chr(((ord(str[i])-97)*k1+k2)%26+65)
        else:
            ans+=str[i]
    return ans

def affine_decrypt(str,k1,k2):
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr((((ord(str[i])-65)-k2)*pow(k1,-1,26))%26+97)
        elif str[i].islower():
            ans+=chr((((ord(str[i])-97)-k2)*pow(k1,-1,26))%26+97)
        else:
            ans+=str[i]
    return ans

str=input("Enter the message: ")
res=affine_decrypt(str,15,20)
print(res)
res=mulcipher_decrypt(str,15)
print(res)
s=addcipher_encrypt(str,20)
print(s)
res=addcipher_decrypt(s,20)
print(res)