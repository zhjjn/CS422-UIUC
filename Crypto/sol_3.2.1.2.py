import sys,urllib
from pymd5 import md5,padding

query_file = sys.argv[1]
command3_file = sys.argv[2]
output_file = sys.argv[3]

with open(query_file) as f:
    query = f.read().strip()

with open(command3_file) as f:
    command3 = f.read().strip()

token = query[query.index("=") + 1 : query.index("&")]
data = query[query.index("&") + 1 :]

h = md5(state = token.decode("hex"), count = 512 * ((len(data) + 8) / 64) + 1)
h.update(command3)

token_new = h.hexdigest()

query_new = "token=" + token_new + "&" + data + urllib.quote(padding((len(data)+8)*8)) + command3

f = open(output_file,"w")
f.write(query_new)
f.close()