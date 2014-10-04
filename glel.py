#!/usr/bin/env python2

import sys, argparse, requests, re, os, yaml, getpass, subprocess

def parseToken(url):
	token = re.search('(?<=#access_token=)[^&]*', url)
	return token.group(0)

def getAccessToken(username, password, sisi):
	data = "UserName=%s&Password=%s" % (username, password)
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

if __name__ == '__main__':
	par = argparse.ArgumentParser(description='steals accounts')
	par.add_argument('-s', '--singularity', action='store_true', help="Use Singularity")
	par.add_argument('-pt', '--ptranq', help="Tranquility Exefile")
	par.add_argument('-ps', '--psisi', help="Singularity Exefile")
	par.add_argument('-u', '--user', help="EVE Online Username")
	par.add_argument('-p', '--pssw', help="EVE Online Password")
	par.add_argument('-w', '--write', action='store_true', help="Writes configuration file")
	args = par.parse_args()
	sisi = args.singularity
	if args.write:
		cfg = file('config.yaml', 'w')
		yaml.dump({'paths': [args.ptranq, args.psisi]}, cfg)
		cfg.close()
	else:
		cfg = file('config.yaml', 'r')
		config = yaml.load(cfg)
		cfg.close()
		if args.user == None:
			username = raw_input("Enter Username: ")
		else:
			uername = args.user
		if args.pssw == None:
			password = getpass.getpass("Enter Password: ")
		else:
			password = args.pssw
		print "Getting access token..."
		access_token = getAccessToken(username, password, sisi)
		print "Getting SSO token..."
		sso_token = getSSOToken(access_token, sisi)
		if sisi:
			print "Starting Singularity"
			subprocess.Popen(['/usr/bin/env', 'wine', config['paths'][1], '/noconsole', '/ssoToken=%s'%sso_token, '/triPlatform=dx9', '/server:singularity'], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
		else:
			print "Starting Tranquility"
			subprocess.Popen(['/usr/bin/env', 'wine', config['paths'][0], '/noconsole', '/ssoToken=%s'%sso_token, '/triPlatform=dx9'], stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
		
