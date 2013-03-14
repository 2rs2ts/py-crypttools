## Author: Andrew Garrett
## Substitution cipher cryptanalysis (no frequency analysis included).
## Usage: python3 sub.py [filename]

import string
import itertools
import copy

def decryptSubCipher(key,ctext):
    """key: a dict of cipherchars to plainchars, ctext: the ciphertext"""
    newtext = ""
    for char in ctext:
        newtext += key[char]
    return newtext

def manipulateSubKey(cipherchar, plainchar, subkey):
    """ cipherchar: an uppercase letter, plainchar: a lowercase letter, """
    """ subkey: the key to which cipherchar will map to plainchar """
    oldplainchar = subkey[cipherchar]
    oldcipherchar = ''
    for cc in subkey:
        if subkey[cc] == plainchar:
            oldcipherchar = cc
    subkey[cipherchar] = plainchar
    if oldcipherchar != '':
        subkey[oldcipherchar] = oldplainchar
    
def sub(SUBCI):
    """ SUBCI: a string in uppercase that is a substitution ciphertext. """
    SUBKEY = {}
    for char in string.ascii_uppercase: SUBKEY[char] = char
    selection = -1
    print()
    while selection != 0:
        print("Choose an option:")
        print("\t0. Exit")
        print("\t1. Print the current decryption of the CIPHERTEXT.")
        print("\t2. Print the current guess of the cipher KEY.")
        print("\t3. MODIFY the cipher key.")
        print("\t4. Attempt a BRUTEFORCE.")
        selection = input(">> ")
        print()
        try:
            selection = int(selection)
        except ValueError:
            selection = -1
        if selection == 0:
            return
        elif selection == 1:
            print("(CIPHERTEXT):",decryptSubCipher(SUBKEY,SUBCI),"\n")
        elif selection == 2:
            print("(KEY):",SUBKEY,"\n")
        elif selection == 3:
            cipherchar = input("(MODIFY): Cipher character: ").upper()
            plainchar = input("(MODIFY): Plain character: ").lower()
            manipulateSubKey(cipherchar, plainchar, SUBKEY)
            print()
        elif selection == 4:
            keywords = input("(BRUTEFORCE): Keywords separated by space: ").lower().replace("  "," ").split()
            tempKey = SUBKEY.copy()
            unknownKeys = []
            unknownVals = list(string.ascii_lowercase)
            for k in SUBKEY:
                if SUBKEY[k].isupper():
                    unknownKeys += k
                else:
                    unknownVals.remove(SUBKEY[k])
            unknownKeys.sort()
            unknownVals.sort()
            allKeyPerms = itertools.permutations(unknownKeys)
            for k in allKeyPerms:
                for x in range(0,len(unknownVals)):
                    tempKey[k[x]] = unknownVals[x]
                decryption = decryptSubCipher(tempKey,SUBCI)
                allin = True
                for keyword in keywords:
                    if keyword not in decryption:
                        allin = False
                        break
                if allin:
                    print("\n(BRUTEFORCE): " + str(tempKey) + "\n" + decryption)
            print()
        else:
            print("That was an invalid selection; I am sorry.","\n")

if __name__ == "__main__":
    import sys
    print("Welcome to the Substitution cipher cryptanalysis tool.")
    if len(sys.argv) > 1:
        print("Ciphertext will be read from file.")
        citext = ""
        for line in open(sys.argv[1]):
            citext += line
        sub("".join(citext.split()).upper())
    else:
        sub("".join(input("Ciphertext: ").split()).upper())
