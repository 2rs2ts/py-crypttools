## Author: Andrew Garrett
## Affine cipher cryptanalysis.
## Usage: python3 aff.py [filename]

def decryptAffCipher(key,ctext):
    """ key: in form (a,b) """
    newtext = ""
    for char in ctext:
        newtext += chr( ((((ord(char) - key[1] - 65) % 26) * computeInverse(key[0])) % 26) + 97)
    return newtext

def computeInverse(a,m=26):
    """ finds inverse of a in mod m via bruteforce """
    for x in range(2,m):
        if (a*x)%m == 1:
            return x
    return 1

def aff(AFFCI):
    """ AFFCI: a string in uppercase that is an affine cipher """
    AFFKEY = [1,0]
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
            print("(CIPHERTEXT):",decryptAffCipher(AFFKEY,AFFCI),"\n")
        elif selection == 2:
            print("(KEY):",AFFKEY,"\n")
        elif selection == 3:
            a = int(input("(MODIFY): a: "))
            b = int(input("(MODIFY): b: "))
            AFFKEY[0] = a
            AFFKEY[1] = b
            print()
        elif selection == 4:
            m = int(input("(BRUTEFORCE): m: "))
            keywords = input("(BRUTEFORCE): Keywords separated by space: ").lower().replace("  "," ").split()
            for a in range(1,m):
                if computeInverse(a) != 1 or a == 1:
                    for b in range(0,m):
                        decryption = decryptAffCipher((a,b),AFFCI)
                        allin = True
                        for keyword in keywords:
                            if keyword not in decryption:
                                allin = False
                                break
                        if allin:
                            print("\n(BRUTEFORCE): key: (" + str(a) +"," + str(b) + ")\n" + decryption)
            print()
        else:
            print("That was an invalid selection; I am sorry.","\n")


if __name__ == "__main__":
    import sys
    print("Welcome to the Affine cipher cryptanalysis tool.\n")
    if len(sys.argv) > 1:
        print("Ciphertext will be read from file.")
        citext = ""
        for line in open(sys.argv[1]):
            citext += line
            aff("".join(citext.split()).upper())
    else:
        aff("".join(input("Ciphertext: ").split()).upper())
