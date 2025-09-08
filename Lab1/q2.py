
def vignere_encrypt(str,key):
    n=len(key)
    j=0
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr((ord(str[i])-65+ord(key[j%n])-97)%26+65)
            j=j+1
        elif str[i].islower():
            ans+=chr((ord(str[i])-97+ord(key[j%n])-97)%26+65)
            j=j+1
        else:
            ans+=str[i]
    return ans

def vignere_decrypt(str,key):
    n=len(key)
    j=0
    ans=""
    for i in range(len(str)):
        if str[i].isspace():
            continue
        if str[i].isupper():
            ans+=chr((ord(str[i])-65-ord(key[j%n])+97)%26+97)
            j=j+1
        elif str[i].islower():
            ans+=chr((ord(str[i])-97-ord(key[j%n])+97)%26+97)
            j=j+1
        else:
            ans+=str[i]
    return ans

def autokey_encrypt(plaintext, key):
    key = key % 26
    keystream = [key]
    ans = ""
    pos = 0
    for ch in plaintext:
        if ch.isspace():
            continue
        if ch.isalpha():
            pval = ord(ch.upper()) - 65
            k = keystream[pos]
            cval = (pval + k) % 26
            ans += chr(cval + 65)
            keystream.append(pval)
            pos += 1
        else:
            ans += ch
    return ans

def autokey_decrypt(ciphertext, key):
    key = key % 26
    keystream = [key]
    ans = ""
    pos = 0
    for ch in ciphertext:
        if ch.isspace():
            continue
        if ch.isalpha():
            cval = ord(ch.upper()) - 65
            k = keystream[pos]
            pval = (cval - k) % 26
            ans += chr(pval + 97)
            keystream.append(pval)
            pos += 1
        else:
            ans += ch
    return ans


str=input("Enter the message: ")
key="dollars"
res=vignere_encrypt(str,key)
print(res)
print(vignere_decrypt(res, key))
res=autokey_encrypt(str,7)
print(res)
print(autokey_decrypt(res,7))
