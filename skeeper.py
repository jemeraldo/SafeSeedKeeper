from Crypto.Cipher import AES
from Crypto.Util import Padding
from base64 import b64decode, b64encode
import os
import json
from pathlib import Path

KEY_LENGTH = 32
IV_LENGTH = 16
PAD_LENGTH = 16

default_questions = (
    'Password',
    'Birth date',
    'City of birth',
    "Mom's name",
    "First pet name",
)
def_q_list = {i+1: q for i, q in enumerate(default_questions)}

def decrypt(body, key: bytes):
    sk, iv = key, key[:16]

    cipher = AES.new(sk, AES.MODE_CBC, IV=iv)
    data = b64decode(body)
    result = Padding.unpad(cipher.decrypt(data), PAD_LENGTH)
    
    return result.decode('utf-8')

def encrypt(data, key: bytes):
    sk, iv = key, key[:16]

    data = data.encode('utf-8')

    cipher = AES.new(sk, AES.MODE_CBC, IV=iv)
    
    result = cipher.encrypt(Padding.pad(data, PAD_LENGTH))
    result = b64encode(result)
    return result.decode('utf-8')

def next_qa():
    print("Write you question or type number of default question. Press enter to continue.")
    for i, q in def_q_list.items():
        print(f"{i}. {q}")
    inp = input("> ")
    if not inp:
        return ("", "")

    try:
        number = int(inp)
        question = def_q_list[number]
    except:
        question = inp
    
    print(f"Type answer for question: {question}")

    inp = input("> ")
    if not inp:
        raise Exception(f"No answer for question {question}")

    return question, inp
        


def create_questions_answers():
    print("Now you can choose secret question and answer, which will be password for encryption. You can choose few secret question and answers sequentially.")
    questions = []
    answers = []
    nq, na = next_qa()
    while(nq != ""):
        questions.append(nq)
        answers.append(na)
        nq, na = next_qa()

    return questions, answers

def get_answers(questions):
    answers = []
    for q in questions:
        print(f"Question: {q}")
        ans = input("Answer: ")
        answers.append(ans)

    return answers


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def key_transform(key, chunk):
    return bytes([(key[i] + chunk[i]) % 256 for i in range(KEY_LENGTH)])

def key_from_answers(answers):
    key = "".join(answers)
    key = key.encode("utf-8")
    init_key = bytes([0])*KEY_LENGTH
    for chk in chunks(key, KEY_LENGTH):
        init_key = key_transform(init_key, Padding.pad(chk, KEY_LENGTH,))

    return init_key

def supposed_file(ext=".txt"):
    files = [f for f in os.listdir('.') if (os.path.isfile(f) and f.endswith(ext) and f != 'requirements.txt')]
    return files[0] if files else ""

def read_data(filename):
    with open(filename, 'r') as f:
        return f.read()

def encrypt_procedure():
    supp_fn = supposed_file(ext=".txt")
    print(f"Input filename: [{supp_fn}] ")
    fn = input() or supp_fn
    if not os.path.isfile(fn):
        raise Exception(f"Could not find input file '{fn}'")
    print(f"Encrypting file " + fn)

    qs, ans = create_questions_answers()
    print("Next answers will be used to encryption. Store them thoroughly!")
    print(ans)
    key = key_from_answers(ans)

    data = read_data(fn)
    result = {}
    result["questions"] = qs
    result["data"] = encrypt(data, key)

    test = decrypt(result["data"], key)
    if test != data:
        raise Exception("Test decryption failed")

    p = Path(fn)
    out_fn = p.stem + "-encrypted" + p.suffix
    with open(out_fn, "w") as f:
        f.write(json.dumps(result))
    print(f"Result saved in {out_fn}")
    

def decrypt_procedure():
    supp_fn = supposed_file(ext="encrypted.txt")
    print(f"Decrypting filename: [{supp_fn}] ")
    fn = input() or supp_fn

    with open(fn, "r") as f:
        body = f.read()
    body = json.loads(body)

    answers = get_answers(body["questions"])
    key = key_from_answers(answers)
    data = decrypt(body["data"], key)

    p = Path(fn)
    out_fn = p.stem + "-decrypted" + p.suffix
    with open(out_fn, "w") as f:
        f.write(data)

    print(f"Decrypted data saved: {out_fn}")
    

if __name__ == '__main__':
    #data = read_data("in.txt")
    #key = key_from_answers(["testtesttest", "123123123123123123123123", "abc", "superpassword123123123"])
    #print(encrypt(data, key))
    #print(decrypt("tMW/AtowbKX3l9LbOZmspA==", key))

    
    print('''Choose action:
1: Encrypt text file with questions(password)
2: Decrypt text file with questions(password)''')
    action = input()

    if action == "1":
        encrypt_procedure()
    elif action == "2":
        decrypt_procedure()
