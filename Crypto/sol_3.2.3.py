import sys
import urllib2

url = "http://cs461-mp3.sprai.org:8081/mp3/zjn1746/?"
#url = "http://127.0.0.1:8081/test/"

def get_status(u):
    req = urllib2.Request(u)
    try:
        f = urllib2.urlopen(req)
        return f.code
    except urllib2.HTTPError, e:
        return e.code

def pad(n):
    n = n%16
    return ''.join(chr(i) for i in range(16,n,-1))


ciphertext_file = sys.argv[1]
output_file = sys.argv[2]

with open(ciphertext_file) as f:
    ciphertext_hex = f.read().strip().decode('hex')

#ciphertext_hex = "580bf2affba4da85e480e53c79b70e7c3c836adf39357555a29aaa86041a38ac58bbda7f5a721c5303a5e7ea291450c0".decode('hex')

blocksize = 16
num_block = len(ciphertext_hex)/blocksize

plain_text = ''

cipher_block = list(ciphertext_hex[0+i:blocksize+i] for i in range(0, len(ciphertext_hex), blocksize))

for i in range(num_block-1):
    plain_block = '\x00'*16
    for j in range(blocksize-1,-1,-1):
        for guess in range(1,256):
            prev_blk = cipher_block[i]
            current_blk = cipher_block[i+1]
            padding = pad(j)
            if j == 15:
                prev_blk_guess = prev_blk[:j] + chr(ord(prev_blk[j]) ^ guess)
            else:
                prev_blk_guess = prev_blk[:j] + chr(ord(prev_blk[j]) ^ guess) + prev_blk[j+1:]
            for k in range(j,blocksize):
                if k == 15:
                    prev_blk_guess = prev_blk_guess[:k] + chr(ord(prev_blk_guess[k]) ^ ord(padding[k-j]))
                else:
                    prev_blk_guess = prev_blk_guess[:k] + chr(ord(prev_blk_guess[k]) ^ ord(padding[k-j])) + prev_blk_guess[k+1:]
            for k in range(j+1,blocksize):
                if k == 15:
                    prev_blk_guess = prev_blk_guess[:k] + chr(ord(prev_blk_guess[k]) ^ ord(plain_block[k]))
                else:
                    prev_blk_guess = prev_blk_guess[:k] + chr(ord(prev_blk_guess[k]) ^ ord(plain_block[k])) + prev_blk_guess[k+1:]
            msg = prev_blk_guess.encode('hex') + current_blk.encode('hex')
            url_ = url + msg
            code = get_status(url_)
            if code != 500:
                plain_block = plain_block[:j] + chr(guess) + plain_block[j+1:]
                print "plain_block: ",plain_block
                break
    plain_text += plain_block
    print plain_text

f = open(output_file, 'w')
f.write(plain_text)
f.close()
