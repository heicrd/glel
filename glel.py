#!/usr/bin/env python2

import sys, argparse, requests, re, os, shelve, getpass, subprocess, hashlib
from Crypto.Cipher import AES
from passlib.hash import pbkdf2_sha256
from urllib import quote as quote

def pad(text):
    return text + b"\0" * (AES.block_size - len(text) % AES.block_size)

def encrypt(password, masterkey, key_size=256):
    padded = pad(password)
    iv = os.urandom(AES.block_size)
    cipher = AES.new(masterkey, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(padded)

def decrypt(encrypted, masterkey):
    iv = encrypted[:AES.block_size]
    cipher = AES.new(masterkey, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted[AES.block_size:])
    return decrypted.rstrip(b"\0")

def parseToken(url):
	token = re.search('(?<=#access_token=)[^&]*', url)
	return token.group(0)

def getAccessToken(username, password, sisi):
	data = "UserName=%s&Password=%s" % (username, quote(password))
	if sisi:
		uri = 'https://sisilogin.testeveonline.com/Account/LogOn?ReturnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3DeveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2Fsisilogin.testeveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken'
		headers = {'Origin': 'https://sisilogin.testeveonline.com', 'Referer': uri, 'Content-type': 'application/x-www-form-urlencoded'}
	else:
		uri = 'https://login.eveonline.com/Account/LogOn?ReturnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3DeveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2Flogin.eveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken'
		headers = {'Origin': 'https://login.eveonline.com', 'Referer': uri, 'Content-type': 'application/x-www-form-urlencoded'}
	r = requests.post(uri, data=data, headers=headers)
	access_token = parseToken(r.url)
	return access_token

def getSSOToken(access_token, sisi):
	if sisi:
		uri = "https://sisilogin.testeveonline.com/launcher/token?accesstoken=%s" % access_token
	else:
		uri = "https://login.eveonline.com/launcher/token?accesstoken=%s" % access_token
	r = requests.get(uri)
	sso_token = parseToken(r.url)
	return sso_token

def setupSettings(config):
	if not 'paths' in config:
		config['paths'] = {}
	if not 'accounts' in config:
		config['accounts'] = {}

if __name__ == '__main__':
	par = argparse.ArgumentParser(description='steals accounts')
	par.add_argument('-a', '--add', action='store_true', help="Store an account")
	par.add_argument('-d', '--delete', action='store_true', help="Delete an account")
	par.add_argument('-s', '--singularity', action='store_true', help="Use Singularity")
	par.add_argument('-pt', '--ptranq', help="Tranquility Exefile")
	par.add_argument('-ps', '--psisi', help="Singularity Exefile")
	par.add_argument('-u', '--user', help="EVE Online Username")
	par.add_argument('-p', '--pssw', help="EVE Online Password")
	par.add_argument('--new-master', action='store_true', help="Set a new master key")
	par.add_argument('-k', '--key', help="Encryption key")
	args = par.parse_args()
	sisi = args.singularity
	config = shelve.open("settings.db", writeback=True)
	setupSettings(config)

	if not 'master' in config or args.new_master:
		one = getpass.getpass("Enter new key: ")
		two = getpass.getpass("Confirm: ")
		if one == two:
			config['master'] = pbkdf2_sha256.encrypt(one, rounds=100000)
		else:
			raise Exception("Passwords must match")

	if args.key == None:
		key = getpass.getpass("Enter Key: ")
	else:
		key = args.key

	if not pbkdf2_sha256.verify(key, config['master']):
		raise Exception("Incorrect master key")
	else:
		key = hashlib.sha256(key).digest()

	if args.ptranq != None:
		config['paths']['tq'] = args.ptranq
	if args.psisi != None:
		config['paths']['sisi'] = args.psisi

	if args.user == None:
		username = raw_input("Enter Username: ")
	else:
		username = args.user

	if args.add:
		newuser = username
		newpass = getpass.getpass("Enter Password for %s: " % newuser)
		newpass2 = getpass.getpass("Confirm: ")
		if newpass == newpass2:
			config['accounts'][newuser] = encrypt(newpass, key)
		else:
			raise Exception("Passwords must match")
		sys.exit()

	if args.delete:
		deluser = username
		confirm = raw_input("Confirm delete %s [y/n]: " % deluser)
		if 'y' in confirm:
			try:
				config['accounts'].pop(deluser)
			except KeyError:
				raise KeyError("User not found")
		sys.exit()

	if args.pssw != None:
		password = args.pssw
	elif username in config['accounts']:
		password = decrypt(config['accounts'][username], key)
	else:
		password = getpass.getpass("Enter Password: ")

	print "Getting access token..."
	access_token = getAccessToken(username, password, sisi)
	print "Getting SSO token..."
	sso_token = getSSOToken(access_token, sisi)

	if sisi:
		print "Starting Singularity"
		subprocess.Popen(['/usr/bin/env', 'wine', config['paths']['sisi'], '/noconsole', '/ssoToken=%s'%sso_token, '/triPlatform=dx9', '/server:singularity'], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
	else:
		print "Starting Tranquility"
		subprocess.Popen(['/usr/bin/env', 'wine', config['paths']['tq'], '/noconsole', '/ssoToken=%s'%sso_token, '/triPlatform=dx9'], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))

