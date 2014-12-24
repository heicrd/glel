#!/usr/bin/env python2

import sys
import os
import argparse
import requests
import re
import shelve
import getpass
import subprocess
import hashlib
import urllib

from Crypto.Cipher import AES
from passlib.hash import pbkdf2_sha256

def pad(text):
	return text + b"\0" * (AES.block_size - len(text) % AES.block_size)

def encrypt(password, key_size=256):
	global key
	try:
		key
	except NameError:
		key = getKey()
	padded = pad(password)
	iv = os.urandom(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return iv + cipher.encrypt(padded)

def decrypt(encrypted):
	global key
	try:
		key
	except NameError:
		key = getKey()
	iv = encrypted[:AES.block_size]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	decrypted = cipher.decrypt(encrypted[AES.block_size:])
	return decrypted.rstrip(b"\0")

def parseToken(url):
	token = re.search('(?<=#access_token=)[^&]*', url)
	return token.group(0)

def getAccessToken(username, password, sisi):
	data = urllib.urlencode({'UserName':username, 'Password':password})
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

def setupSettings():
	if not 'paths' in config:
		config['paths'] = {}
	if not 'accounts' in config:
		config['accounts'] = {}

def setKey():
	key1 = getpass.getpass("Enter new key: ")
	key2 = getpass.getpass("Confirm: ")
	try:
		if key1 == key2:
			config['key'] = pbkdf2_sha256.encrypt(key1, rounds=100000)
			print "Deleting account data"
			config['accounts'].clear()
		else:
			raise Exception("Passwords must match")
	except:
		print "Passwords must match"
		setKey()
	print "Key set. Exiting."
	sys.exit()

def getKey():
	if args.key is None:
		ikey = getpass.getpass("Enter Key: ")
	else:
		return args.key
	if pbkdf2_sha256.verify(ikey, config['key']):
		rkey = hashlib.sha256(ikey).digest()
	else:
		raise Exception("Incorrect key")
	return rkey

def getPass(password, username=None):
	if password is not None:
		rpass = password
	elif config is not None:
		if key is not None and username is not None and username in config['accounts']:
			rpass = decrypt(config['accounts'][username])
		elif key is None and username is not None and username in config['accounts']:
			rpass = decrypt(config['accounts'][username])
		else:
			print "User not in database"
			rpass = getpass.getpass("Enter Password: ")
	else:
		print "User not in database"
		rpass = getpass.getpass("Enter Password: ")
	return rpass

def addAcct(newuser, newpass):
	if newpass is None:
		newpass1 = getpass.getpass("Enter Password for %s: " % newuser)
		newpass2 = getpass.getpass("Confirm: ")
		try:
			if newpass1 == newpass2:
				config['accounts'][newuser] = encrypt(newpass1)
			else:
				raise Exception("Passwords must match")
		except Exception, e:
			print e
			addAcct(newuser, newpass)
	else:
		config['accounts'][newuser] = encrypt(newpass)

def delAcct(user, confirm):
	if confirm is None:
		confirm = raw_input("Confirm delete %s [y/n]: " % user)
	if 'y' in confirm:
		try:
			config['accounts'][user] = os.urandom(64)
			config['accounts'].pop(user)
			config.sync()
		except KeyError:
			raise KeyError("User not found")
	else:
		print "Aborted."
		sys.exit()

def launch(username, password, sisi):
	accessToken = getAccessToken(username, password, sisi)
	ssoToken = getSSOToken(accessToken, sisi)
	try:
		if sisi:
			print "Starting Singularity"
			subprocess.Popen(['/usr/bin/env', 'wine', config['paths']['sisi'], '/noconsole', '/ssoToken=%s' % ssoToken, '/triPlatform=dx9', '/server:singularity'], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
		else:
			print "Starting Tranquility"
			subprocess.Popen(['/usr/bin/env', 'wine', config['paths']['tq'], '/noconsole', '/ssoToken=%s' % ssoToken, '/triPlatform=dx9'], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
	except KeyError:
		raise KeyError("EVE Online not found")

if __name__ == '__main__':
	par = argparse.ArgumentParser(description='steals accounts')
	par.add_argument('-a', '--add', action='store_true', help="Store an account")
	par.add_argument('-r', '--remove', dest='delete', action='store_true', help="Removes an account")
	par.add_argument('-s', '--singularity', action='store_true', help="Use Singularity")
	par.add_argument('-pt', '--ptranq', help="Tranquility Exefile")
	par.add_argument('-ps', '--psisi', help="Singularity Exefile")
	par.add_argument('-u', '--user', help="EVE Online Username")
	par.add_argument('-p', '--pass', dest='pssw', help="EVE Online Password")
	par.add_argument('--new-key', action='store_true', help="Set a new key")
	par.add_argument('-k', '--key', help="Encryption key")
	par.add_argument('-y', '--yes', action='store_const', const="yes", help="Bypass deletion confirmation")
	par.add_argument('-nc', '--no-check', action='store_true', help="Do not check settings for account password")
	par.add_argument('-d', '--debug', action='store_true', help="Do not log into EVE Online")
	args = par.parse_args()
	sisi = args.singularity
	config = shelve.open("settings.db", writeback=True)
	setupSettings()

	if not 'key' in config or args.new_key:
		setKey()

	if args.user is not None:
		username = args.user
	else:
		username = raw_input("Enter Username: ")

	if args.ptranq is not None:
		config['paths']['tq'] = args.ptranq
	if args.psisi is not None:
		config['paths']['sisi'] = args.psisi

	if args.add:
		addAcct(username, args.pssw)

	if args.delete:
		delAcct(username, args.yes)

	if args.delete is False and args.add is False and args.debug is False:
		if args.no_check == False:
			password = getPass(args.pssw, username)
		elif args.pssw is not None:
			password = args.pssw
		else:
			password = getpass.getpass("Enter Password: ")
		launch(username, password, sisi)
