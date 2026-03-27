import os
import sys
import filecmp

if os.name == 'posix':
  # Linux, MacOS
  import pexpect as exp
else: 
  # Windows
  import wexpect as exp

tool = 'target/release/cryptcrypt'

# create test file
print('Cleartext 42', file=open('test.txt', 'w'))

# encrypt test file
child = exp.spawn(f'{tool} test.txt')
child.expect('password:')
child.sendline('pass')
child.expect('password:')
child.sendline('pass')
child.expect (exp.EOF)

# backup test file
os.replace('test.txt', 'test.org')

# decrypt .cce file
child = exp.spawn(f'{tool} -d test.txt.cce')
child.expect('password:')
child.sendline('pass')
child.expect (exp.EOF)

# compare decrypted file against backup
if filecmp.cmp('test.txt', 'test.org'):
  print("Test ok")
  sys.exit(0)
else:
  print("Test failed")
  sys.exit(1)
