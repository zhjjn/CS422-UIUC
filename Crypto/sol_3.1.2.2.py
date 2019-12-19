import sys,getopt
from Crypto.Cipher import AES

def main(argv):
    opts, args = getopt.getopt(argv, '', ["ifile=","ifile2=","ifile3=","ofile="])
    ciphertext_file=args[0]
    key_file=args[1]
    iv_file=args[2]
    output_file=args[3]

    with open(ciphertext_file) as f:
        ciphertext = f.read().strip()
        ciphertext_bin = ciphertext.decode('hex')
    
    with open(key_file) as f:
        key = f.read().strip()
        key_bin = key.decode('hex')

    with open(iv_file) as f:
        iv = f.read().strip()
        iv_bin = iv.decode('hex')


    output_f = open(output_file,"w")
    decryptor = AES.new(key_bin,AES.MODE_CBC,IV = iv_bin)
    plaintext = decryptor.decrypt(ciphertext_bin)
    output_f.write(plaintext)
    output_f.close()
    

if __name__ == "__main__":
    main(sys.argv[1:])