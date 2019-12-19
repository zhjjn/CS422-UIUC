import sys,getopt

def main(argv):
    opts, args = getopt.getopt(argv, '', ["ifile=","ifile2=","ofile="])
    ciphertext_file=args[0]
    key_file=args[1]
    output_file=args[2]

    dict={}

    with open(key_file) as key_f:
        key = key_f.read().strip()

    letter_decrypt='A'
    for letter_encryt in key:
        dict[letter_encryt]=letter_decrypt
        letter_decrypt=chr(ord(letter_decrypt)+1)

    with open(ciphertext_file) as f:
        ciphertext = f.read().strip()

    output_f = open(output_file,"w")
    for s in ciphertext:
        if s==' ':
            output_f.write(s)
        elif s.isdigit():
            output_f.write(s)
        else:
            output_f.write(dict[s])

    output_f.close()

if __name__ == "__main__":
    main(sys.argv[1:])