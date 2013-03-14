## Author: Andrew Garrett
## Vigenere cipher cryptanalysis.
## Usage: python3 vig.py [mode] [filename]
##        Where mode is either "-c" for classic or "-s" for stream and
##        filename is the name of a text file that contains a Vigenere
##        ciphertext.
## Note: ciphertext and key values are upper case, plaintext is lower case.

## The stream mode refers to a modified Vigenere cipher in which the Vigenere
## key is the seed for a stream cipher generator: for every i=0... group of
## j=0..n integers of the key v where n is the length of the Vigenere seed (the
## word with which Vigenere encrypts) the value of the stream is (v_j + i) mod m
## In other words the cipher right shifts every char of the key by 1 (mod m)
## each time the key "rolls over." The intent is to add the property of
## confusion, but it fails at adding the property of diffusion since each
## character of plaintext directly correlates to one character of ciphertext.
## It is still vulnerable to the Kasiski test as well. This tool includes an
## algorithm for finding the indices of coincidence.

import itertools
import string

class Vigkey:
    """ A container for a Vigenere cipher key, offers stream output.
    Only supports Z26 at this time.
    """
    #__slots__ = ["key","isStream"]

    def __init__(self,key,isStream=False):
        """ Create a new Vigkey containing a key.

        Arguments:
        key - must be an iterable of strings of length 1, e.g. a string
              is expected to be alphabetic and is converted to uppercase.
              represented as a list of uppercase characters.
        isStream - True if the Vigkey applies to the modified Vigenere cipher.
                   (default False)

        Raises:
        ValueError - if key provided is not at least length 1 or if the iterable
                     contains strings that are not one character long or data
                     that is not a string.
        """
        if len(key) < 1:
            raise ValueError("key must be at least length 1")
        for char in key:
            if not isinstance(char,str) or len(char) != 1:
                raise ValueError("key must contain only strings of length 1")
        self.key = [char.upper() for char in key]
        self.isStream = isStream
        self.keyPointer = 0
        self.keyIncrement = 0
        self.m = 26
        self.ordOffset = 65

    def __str__(self):
        """ Give a string representation of the Vigkey.

        Format:
        Vigkey: (stream) <key value>
        """
        keyStr = "Vigkey: "
        if self.isStream:
            keyStr += "(stream) "
        keyStr += str(self.key)
        return keyStr

    def nextChar(self):
        """ Give the next character in the key. Loops over the key infinitely.
        """
        returnedChar = chr(                                                 \
                            (                                               \
                                ((ord(self.key[self.keyPointer])            \
                                + self.keyIncrement)                        \
                                - self.ordOffset)                           \
                                % self.m                                    \
                             ) + self.ordOffset                             \
                           )
        self.keyPointer = (self.keyPointer + 1) % len(self.key)
        if self.keyPointer == 0 and self.isStream:
            self.keyIncrement = (self.keyIncrement + 1) % self.m
        return returnedChar

    def reset(self):
        """ Set the key pointer and the stream increment back to 0.
        """
        self.keyPointer = 0
        self.keyIncrement = 0

def decryptVigCipher(key,ctext,m=26):
    """ Apply a Vigenere key to a ciphertext.

    Arguments:
    key - must be a Vigkey
    ctext - must be an iterable of strings of length 1, e.g. a string
    m - the size of the integer ring Zm, must be a positive int (default 26)

    Returns:
    The decoded ciphertext.

    Raises:
    ValueError - if key is not a Vigkey or if ctext is not long enough
    TypeError - if ctext is not an iterable of strings of length 1
    """
    if not isinstance(key,type(Vigkey("FOO"))):
        raise TypeError("key must be a Vigkey.")
    try:
        if len(ctext) < 1:
            raise ValueError("ctext is not sufficiently long.")
        elif not isinstance(ctext[0],str):
            raise TypeError()
    except TypeError:
        raise TypeError("ctext must be an iterable (of strings).")
    newtext = str()
    for char in ctext:
        newtext += chr(                                                     \
                        ((ord(char) - ord(key.nextChar()))                  \
                         % m)                                              \
                        + 97)
    return newtext

def divideIntoSubstrings(ctext,n=1,STREAM_MODE=False,m=26):
    """ Divide a Vigenere cipher into substrings.

    Arguments:
    ctext - must be an iterable of strings, e.g. a string
    n - the number of substrings requested, must be a positive int (default 1)
    STREAM_MODE - True if the cipher is the modified Vigenere cipher.
                  (default False)
    m - the size of the integer ring Zm, must be a positive int (default 26)

    Returns:
    A list of length n of strings, where each string in the list is a substring
    of ctext where the (n+i)-th character from i = 0 to i = n-1 for every n
    characters of ctext is a substring of the i-th substring of the returned
    list, and the i-th substring is built in order of each (n+i)-th character's
    appearance in ctext. For example:
    (3, "Hello world!") -> ["Hlwl","eood","l r!"]

    Raises:
    TypeError - if m or n are not ints or if ctext is not an iterable of chars
    ValueError - if m or n are not positive ints or if ctext is not at least of
                 length n.
    """
    if not isinstance(m,int) or not isinstance(n,int):
        raise TypeError("m and n must be of type int.")
    elif n < 1 or m < 1:
        raise ValueError("m and n must be at least 1.")
    try:
        if len(ctext) < n:
            raise ValueError("Not a long enough cipher for the number of " +\
                             "substrings you requested.")
        if not isinstance(ctext[0],str):
            raise TypeError()
    except TypeError:
        raise TypeError("ctext must be an iterable (of strings).")
    substrings = [str() for i in range(0,n)]
    k = 0
    offset = 0
    for char in ctext:
        substrings[k] += chr(                                               \
                                (                                           \
                                    ((ord(char)-65) - offset )              \
                                % m)                                        \
                            + 65)
        k = (k + 1) % n
        if STREAM_MODE and k == 0:
            offset = (offset + 1) % m
    return substrings

def findIndicesOfCoincidence(substrings,m=26):
    """ Finds n indices of coincidence for a set of n substrings.

    Arguments:
    substrings - a list of strings (assumed to be all caps)
    m - the size of the integer ring Zm, must be a positive int (default 26)

    Returns:
    A list of ints, where the i-th element from 0 to n, the length of
    substrings, of the returned list is the index of coincidence of the i-th
    substring in substrings. This is the general form of a function that
    finds the index of coincidence of a string. It may be used for the modified
    Vigenere cipher as well.

    Throws:
    TypeError - if m is not an int or substrings is not a list of strings
    ValueError - if m is not a positive int or substrings is empty
    """
    if not isinstance(m,int):
        raise TypeError("m must be of type int.")
    elif m < 1:
        raise ValueError("m must be a positive int.")
    if not isinstance(substrings,list):
        raise TypeError("substrings must be a list.")
    if len(substrings) < 1:
        raise ValueError("substrings must contain at least one element.")
    elif not isinstance(substrings[0],str):
        raise TypeError("substrings must be a list of strings.")
    indices = list()
    for substring in substrings:
        index = 0
        for i in range(0,m):                # For each in Zm count incidences fi
            fi = 0
            for char in substring:
                if i == ( (ord(char)-65) % m):
                    fi += 1
            index += (fi * (fi - 1))
        index /= (len(substring) * (len(substring) - 1))
        indices.append(index)
    return indices

def findPossibleKeys(substrings,FREQTABLE,m=26):
    """ Once a likely key length has been decided, you can guess the key.

    Arguments:
    substrings - a list of strings (assumed to be all caps)
    FREQTABLE - a list of probabilities (0 to 1) of a symbol occurring in
                a body of text. Must be mapped from 0 to m.
    m - the size of the integer ring Zm, must be a positive int (default 26)

    Returns:
    

    Throws:
    TypeError - if m is not an int or FREQTABLE is not a list of probabilities
                or substrings is not a list of strings
    ValueError - if m is not a positive int or substrings is empty or
                 FREQTABLE's length does not match m
    """
    if not isinstance(m,int):
        raise TypeError("m must be of type int.")
    elif m < 1:
        raise ValueError("m must be a positive int.")
    if not isinstance(substrings,list):
        raise TypeError("substrings must be a list.")
    if len(substrings) < 1:
        raise ValueError("substrings must contain at least one element.")
    elif not isinstance(substrings[0],str):
        raise TypeError("substrings must be a list of strings.")
    if not isinstance(FREQTABLE,list):
        raise TypeError("FREQTABLE must be a list.")
    if len(FREQTABLE) != m:
        raise ValueError("FREQTABLE's size must match m.")
    elif not isinstance(FREQTABLE[0],float):
        raise TypeError("FREQTABLE must be a list of probabilities.")
    
    keyCandidates = list()                  # Possible keys
    keyLetters = list()                     # Possible letters for all ki

    def buildKeys(keyLetters=keyLetters):
            """ Helper function: recursively build the keys.
            Warning: exponential complexity.

            Arguments:
            keyLetters - a list of strings, it should be the keyLetters above.

            Returns:
            A list of strings, the possible keys.
            """
            keyPossibilities = list()
            if len(keyLetters) == 1:
                keyPossibilities = [l for l in keyLetters[0]]
            else:
                for letter in keyLetters[0]:
                    nextChars = buildKeys(keyLetters[1:])
                    for char in nextChars:
                        if (letter + char) not in keyPossibilities:
                            keyPossibilities.append(letter + char)
            return keyPossibilities
    
    for substring in substrings:
        for k in range(0,len(substrings)):
            kLetters = list()               # Possible letters for this ki
            for g in range(0,m):
                mg = 0
                for i in range(0,m):
                    fgi = 0                 # Number of letter i in substring
                    for char in substring:
                        if i == ( (ord(char)-g-65) % m):
                            fgi += 1
                    mg += ((FREQTABLE[i]*fgi) / len(substring))
                if mg > 0.06 and mg < 0.07:
                    kLetters.append( chr(g+65) )
            if len(kLetters) == 0:
                for char in string.ascii_uppercase:
                    kLetters.append(char)
            if kLetters not in keyLetters:
                keyLetters.append(kLetters)
    for key in buildKeys(keyLetters):
        if key not in keyCandidates:
            keyCandidates.append(key) 
    return keyCandidates

def vig(VIGCI,STREAM_MODE=False):
    """ Cryptanalyze a Vigenere cipher.

    Arugments:
    VIGCI: a string in uppercase that is a Vigenere cipher.
    STREAM_MODE: true if working with a modified stream/Vigenere cipher hybrid
                 (from a homework assignment)
    """
    VIGKEY = Vigkey("VIGENERE",STREAM_MODE)
    VIGDIV = divideIntoSubstrings(VIGCI,1,STREAM_MODE)
                                            # The substring-divided ciphertext
    FREQTABLE = [ 0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061,   \
                  0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019,   \
                  0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.001,   \
                  0.020, 0.001 ]            # The table of English letter freqs
    selection = -1
    print()
    while selection != 0:
        print("Choose an option:")
        print("\t0. EXIT")
        print("\t1. Toggle classic or stream Vigenere cipher MODE.")
        print("\t2. Print the current DECRYPTION of the ciphertext.")
        print("\t3. Print the current guess of the cipher KEY.")
        print("\t4. MODIFY the cipher key.")
        print("\t5. DIVIDE the cipher into substrings.")
        print("\t6. Find the INDICES of coincidence in the cipher substrings.")
        print("\t7. Compute the POSSIBLE keys based on the cipher substrings.")
        print("\t8. Attempt a BRUTEFORCE.")
        selection = input(">> ")
        print()
        try:
            selection = int(selection)
        except ValueError:
            selection = -1
        if selection == 0:
            pass
        elif selection == 1:
            STREAM_MODE = not STREAM_MODE
            if STREAM_MODE:
                print("(MODE): Stream Vigenere cipher.")
            else:
                print("(MODE): Classic Vigenere cipher.")
            VIGKEY = Vigkey(VIGKEY.key,STREAM_MODE)
        elif selection == 2:
            print("(DECRYPTION):",decryptVigCipher(VIGKEY,VIGCI),"\n")
            VIGKEY.reset()
        elif selection == 3:
            print("(KEY):",str(VIGKEY),"\n")
        elif selection == 4:
            VIGKEY = Vigkey([char.upper() for char in                       \
                             input("(MODIFY): Type new key: ")]             \
                            , STREAM_MODE)
            print()
        elif selection == 5:
            n = int(input("(DIVIDE): key length n: "))
            if n < 1:
                n = 1
            VIGDIV = divideIntoSubstrings(VIGCI, n, STREAM_MODE)
            k = 0
            for division in VIGDIV:
                print("\n" + str(k) + ": " + division)
                k += 1
            print()
        elif selection == 6:
            indices = findIndicesOfCoincidence(VIGDIV)
            print("\n(INDICES): For key length",len(VIGDIV),"the indices are:")
            for index in indices:
                if index > 0.06 and index < 0.07:
                    print(index,"(A good index!)")
                else:
                    print(index)
            print()
        elif selection == 7:
            possibleKeys = findPossibleKeys(VIGDIV,FREQTABLE)
            print("(POSSIBLE): "+str(possibleKeys)+"\n")
        elif selection == 8:
            keylength = int(input("(BRUTEFORCE): Key length: "))
            keywords = input("(BRUTEFORCE): Keywords separated by space: ") \
                       .lower().replace("  "," ").split()
            keyset = ("".join(s) for s in                                   \
                            itertools.product(                              \
                                                string.ascii_uppercase,     \
                                                repeat=keylength            \
                                              )                             \
                                            if s[:keylength//2]             \
                                            !=s[keylength//2:] )
            for key in keyset:
                vkey = Vigkey(key, STREAM_MODE)
                decryption = decryptVigCipher(vkey, VIGCI)
                vkey.reset()
                allin = True
                for keyword in keywords:
                    if keyword not in decryption:
                        allin = False
                        break
                if allin:
                    print("\n(BRUTEFORCE): key:",str(vkey),"\n" + decryption)
            print()
        else:
            print("That was an invalid selection; I am sorry.","\n")
    return

if __name__ == "__main__":
    import sys
    print("Welcome to the Vigenere cipher cryptanalysis tool.\n")
    STREAM_MODE = False
    if len(sys.argv) == 1:
        mode = input("Mode not specified. Mode? (c for classic, s for stream) ")
        if mode == "s":
            STREAM_MODE = True
            print("Mode selected: Stream.")
    elif sys.argv[1] == "-s":
        STREAM_MODE = True
    elif sys.argv[1] != "-c":
        print("Usage: python3 vig.py mode [filename]", file=sys.stderr)
    if len(sys.argv) > 2:
        print("Ciphertext will be read from file.")
        ctext = str()
        for line in open(sys.argv[1]):
            ctext += line
        vig("".join(ctext.split()).upper(), STREAM_MODE)
    else:
        vig("".join(input("Ciphertext: ").split()).upper(), STREAM_MODE)
