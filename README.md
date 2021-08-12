# Scripts for machines on TryHackMe

rocket_reset_shell.py - is a modification of the "Rocket.Chat 3.12.1 - NoSQL Injection to RCE (Unauthenticated)" CVE2021-22911 script on exploitdb thanks to enox
  - added threading to the password reset
  - added a perl reverse shell
  - removed 2FA as it is not needed for this box

crackhead.py - is a threaded hash cracker for md5, sha1 and sha256 hashes for the Python for Pentesters room 

chronicle.py - ROP chain exploit for chronicle machine, leaks puts even though ASLR isnt even enabled, but why?
