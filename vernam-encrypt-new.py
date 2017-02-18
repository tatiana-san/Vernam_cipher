#python 2.7
import binascii, math, random, array

plaintext_ascii="Convert binary data to a line of ASCII characters." #Plaintext
plaintext_bin="" #plaintext as string of bits
plaintext_bytes=[] #binary plaintext splitted into array of bytes

key_bin="" #key as a 32-bit string
key_bytes=[] #key as array of bytes

ciphertext_ascii=""
ciphertext_bin=""
ciphertext_bytes=[]

text_decrypted_bin=""
text_decrypted_bytes=[]
text_decrypted_ascii=""

guess_key_bytes_shifted_bin="" #will be used for testing keys during attack

#Convert plaintext from ascii to bin:
for c in plaintext_ascii:
    plaintext_bin+=format(ord(c), '08b')

#Create array of bytes of plaintext:
for i in range(0,len(plaintext_bin)/8):
    plaintext_bytes.append(plaintext_bin[i*8:i*8+8])

#Generate random 32-bit key:
random_bit=0
for i in range(0,32):
    random_bit=int(random.randint(0,1))
    key_bin+=str(random_bit)
    key_bytes.append(random_bit)

#Compute ciphertext by XORing plaintext with the key:
count=0
key_print="" #this is the random encryption key repeated to be equal to the length of the plaintext - used only for testing
for i in range(0,len(plaintext_bin)):
    if count<32:
        ciphertext_bin+=str(int(key_bin[count])^int(plaintext_bin[i]))
        key_print+=key_bin[count]
        count+=1
    else:
        count=0
        ciphertext_bin+=str(int(key_bin[count],2)^int(plaintext_bin[i],2))
        key_print+=key_bin[count]
        count+=1

#Split ciphertext into bytes:
for i in range(0,len(ciphertext_bin)/8):
    ciphertext_bytes.append(ciphertext_bin[i*8:i*8+8])
    ciphertext_ascii+=chr(int(ciphertext_bytes[i],2))
    
print "Plaintext :", plaintext_ascii
print "Ciphertext:", ciphertext_ascii
#print "Plaintext :", plaintext_bin         #Uncomment these 3 items to make sure that XOR is working correctly
#print "Random key:", key_print
#print "Ciphertext:", ciphertext_bin, "\n"

############## Attack ############################
# The attack is based on searching for a 4-letters template (i.e. 4 bytes). This template is XORed with 4 bytes of ciphertext in order to get a guess_key.
# The process loops through the bytes of ciphertext: for instance, in the ciphertext "xxxxxxxx" the template "the " would generate 5 guess keys, as it can be
# at 5 different positions in the plaintext. If the XOR operation starts not from byte 0, 4, 8 etc of the ciphertext, the bytes of the guess key are shifted
# in order to be usable for decryption.
# Each guess key is used to decrypt the ciphertext. All possible variants are listed upon the attack completion. Whatever makes sence, is the plain text.  

print "\n### Attack ###\n"

temp_ascii=" of "  # 4 byte test word, or template
temp_bin="" #template as a string of bits

#Convert test word into bin:
for c in temp_ascii:
    temp_bin+=format(ord(c), '08b')

shift=0 #indicates the position of the first byte of ciphertext that is currently being checked. It is zero if the position is 0, 4, 8...
#1 if the position is 1,5,9...; 2 if position is 2, 6, 10... and 3 if position is 3, 7, 11... E.g., If in the ciphertext "This is a page" the 4 bytes "is i"
#are being analysed, then the shift will be 2.

for i in range(0,len(ciphertext_bytes)-len(temp_ascii)+1):   # for each byte of the ciphertext that could be the first byte of encrypted test word 
    guess_key=""
    guess_key_bytes=[]
    guess_key_bytes_shifted=["0","0","0","0"]
    guess_key_bytes_shifted_bin=""
    text_decrypted_bin=""
    text_decrypted_bytes=[]
    text_decrypted_ascii="" # used to display each variant of decryption (for each guess key)

    for b in range(0,len(temp_bin)): #calculate guess key for this position i
        guess_key+=str(int(ciphertext_bin[i*8+b],2)^int(temp_bin[b],2))   
        
    for y in range(0,len(guess_key)/8):   #split bin string of guess key into bytes
        guess_key_bytes.append(guess_key[y*8:y*8+8])
    
    #Adjust the order of bytes of the guess key depending on the current position in the ciphertext: 

    if shift==0:
        guess_key_bytes_shifted=guess_key_bytes

    elif shift==1: 
        guess_key_bytes_shifted[0]=guess_key_bytes[3]
        guess_key_bytes_shifted[1]=guess_key_bytes[0]
        guess_key_bytes_shifted[2]=guess_key_bytes[1]
        guess_key_bytes_shifted[3]=guess_key_bytes[2]

    elif shift==2: 
        guess_key_bytes_shifted[0]=guess_key_bytes[2]
        guess_key_bytes_shifted[1]=guess_key_bytes[3]
        guess_key_bytes_shifted[2]=guess_key_bytes[0]
        guess_key_bytes_shifted[3]=guess_key_bytes[1]

    elif shift==3: 
        guess_key_bytes_shifted[0]=guess_key_bytes[1]
        guess_key_bytes_shifted[1]=guess_key_bytes[2]
        guess_key_bytes_shifted[2]=guess_key_bytes[3]
        guess_key_bytes_shifted[3]=guess_key_bytes[0]

    #Create a string with a guess key shifted:
    for w in range(0,len(guess_key_bytes_shifted)):
        guess_key_bytes_shifted_bin+=guess_key_bytes_shifted[w]

    #Try to derypt the ciphertext with this shifted key:
    count2=0
    for a in range(0,len(ciphertext_bin)):
        if count2<32:
            text_decrypted_bin+=str(int(guess_key_bytes_shifted_bin[count2],2)^int(ciphertext_bin[a],2))
            count2+=1
        else:
            count2=0
            text_decrypted_bin+=str(int(guess_key_bytes_shifted_bin[count2],2)^int(ciphertext_bin[a],2))
            count2+=1

    #Split decrypted text into bytes:
    for r in range(0,len(text_decrypted_bin)/8):
        text_decrypted_bytes.append(text_decrypted_bin[r*8:r*8+8])

    #Convert decrypted text into readable symbols:
    for q in range(0,len(text_decrypted_bytes)):
        text_decrypted_ascii+=chr(int(text_decrypted_bytes[q],2))

    #Print out the result: all variants of decrypted texts along with the corresponding keys    
    print "Decrypted:", text_decrypted_ascii, "- variant", i, ", key=", guess_key_bytes_shifted_bin, "\n"

    #Shifting
    if shift<3: 
        shift+=1
    else:
        shift=0
