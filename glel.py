#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import os
import argparse
import requests
import re
import sqlite3
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

def setKey():
	key1 = getpass.getpass("Enter new key: ")
	key2 = getpass.getpass("Confirm: ")
	try:
		if key1 == key2:
			cur.execute("INSERT OR REPLACE INTO Thing VALUES(?, ?)", ('Key', pbkdf2_sha256.encrypt(key1, rounds=100000)))
			print "Deleting account data"
			cur.execute("DELETE FROM Accounts")
			conn.commit()
		else:
			raise Exception("Passwords must match")
	except Exception, e:
		print e
		conn.close()
		sys.exit(1)
	print "Key set. Exiting."
	conn.close()
	sys.exit(0)

def getKey():
	if args.key is None:
		ikey = getpass.getpass("Enter Key: ")
	else:
		ikey = args.key
	cur.execute("SELECT * FROM Thing WHERE Which='Key'")
	if pbkdf2_sha256.verify(ikey, cur.fetchone()[1]):
		rkey = hashlib.sha256(ikey).digest()
	else:
		raise Exception("Incorrect key")
	return rkey

def getPass(username=None, password=None):
	if password is not None:
		rpass = password
	else:
		cur.execute("SELECT * FROM Accounts WHERE User = ?", (username,))
		info = cur.fetchone()
		if username is not None and info is not None:
			rpass = decrypt(info[1])
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
				cur.execute("INSERT OR REPLACE INTO Accounts VALUES(?, ?)", (newuser, buffer(encrypt(newpass1))))
				conn.commit()
			else:
				raise Exception("Passwords must match")
		except Exception, e:
			print e
			addAcct(newuser, newpass)
	else:
		cur.execute("INSERT OR REPLACE INTO Accounts VALUES(?, ?)", (newuser, buffer(encrypt(newpass1))))
		conn.commit()

def delAcct(user, confirm):
	if confirm is None:
		confirm = raw_input("Confirm delete %s [y/n]: " % user)
	if 'y' in confirm:
		try:
			print "deleting %s" % user
			cur.execute("DELETE FROM Accounts WHERE User = ?", (user,))
			conn.commit()
			conn.close()
			sys.exit(0)
		except KeyError:
			raise KeyError("User not found")
	else:
		print "Aborted."
		conn.close()
		sys.exit(0)

def launch(username, password, sisi):
	accessToken = getAccessToken(username, password, sisi)
	ssoToken = getSSOToken(accessToken, sisi)
	try:
		if sisi:
			print "Starting Singularity"
			cur.execute("SELECT * FROM Thing WHERE Which='SiSi'")
			path = cur.fetchone()[1]
			subprocess.Popen(['/usr/bin/env', 'wine', path, '/noconsole', '/ssoToken=%s' % ssoToken, '/triPlatform=dx9', '/server:singularity'], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
		else:
			print "Starting Tranquility"
			cur.execute("SELECT * FROM Thing WHERE Which='TQ'")
			path = cur.fetchone()[1]
			subprocess.Popen(['/usr/bin/env', 'wine', path, '/noconsole', '/ssoToken=%s' % ssoToken, '/triPlatform=dx9'], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
	except TypeError:
		raise TypeError("EVE Online location not set")

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
	args = par.parse_args()
	sisi = args.singularity

	try:
		conn = sqlite3.connect('settings.sqlite')
		cur = conn.cursor()
	except:
		raise Exception("something went wrong opening the settings file")

	cur.executescript("""
		CREATE TABLE IF NOT EXISTS Thing(Which PRIMARY KEY, What TEXT);
		CREATE TABLE IF NOT EXISTS Accounts(User PRIMARY KEY, Pass BLOB);
		""")

	if args.ptranq is not None:
		cur.execute("INSERT OR REPLACE INTO Thing VALUES(?, ?)", ('TQ', args.ptranq))
		conn.commit()
	if args.psisi is not None:
		cur.execute("INSERT OR REPLACE INTO Thing VALUES(?, ?)", ('SiSi', args.psisi))
		conn.commit()

	cur.execute("SELECT * FROM Thing WHERE Which='Key'")
	check = cur.fetchone()

	if check is None or args.new_key:
		setKey()

	if args.user is not None:
		username = args.user
	else:
		username = raw_input("Enter Username: ")

	if args.add:
		addAcct(username, args.pssw)

	if args.delete:
		delAcct(username, args.yes)

	if args.delete is False and args.add is False:
		if args.no_check == False:
			password = getPass(username, args.pssw)
		elif args.pssw is not None:
			password = args.pssw
		else:
			password = getpass.getpass("Enter Password: ")
		launch(username, password, sisi)
	
	conn.close()
