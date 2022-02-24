#!/usr/bin/env python3

import sys
import unittest
from os import path, remove
from jwt import InvalidTokenError

# Add the src directory to path
sys.path.append(path.join(path.dirname(path.dirname(path.abspath(__file__))), 'src'))

from elections import Backend, UnauthorisedException, AccountExistsException, AccountNotFoundException

test_priv_rsa_key = b'''-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgH0jEFHRr5bMjhOrIc15XYuZNYlpYstj2U7LICTTx6uno/z7+xdv
dQwJkjCTkNgmxyB8u8z6vn0bGT0uFzQyjZihQFGLzcAGsBsOobqJXryHsb3hcp/W
M1jtdW9fwGbMVUYVym0/YV83nG0F2ei4wzgn+iviXud5/WXOogDFxzQLAgMBAAEC
gYA+YtnDALf6hVabxaifiM8zRpmjPRAM+GWhW7FVyuNz16rw+CsRXvbKnobsgtUm
fgauUqFKKwQG2Ri3IKBe3IksgDcBiQ4d1Q4li9v1Yx3HTnuJbtu8OiA9w5/OxiTy
I2WSCy8MSr6A1eGk/TUHjzyTtgOGlKWNL0fbuY9E2eAEGQJBAPYhH23D8Zm/ETs5
n7oMygQfdBZL4t24aZbaUtdO46d58kEWdL4o+LttAnpIuysQyRLfgSEgZXNAdHy7
FZNl4H8CQQCCJ8b8Z4o3+cUaY8cbC9GeorAiURg8fnov7UK03wvfpovGt2gadoty
2YcPBrU/4GdOJohfYZxqqQSFURcsu2Z1AkAajFYUg+cie06DgeKtscV0jmP6J7NP
0R1qjSAUY0kA/pFX3fE3tbmmlcqHoCK4MXZO19bY2OK4fMJT1eYs4PdHAkBBuN5E
8++ahlgeFEYlBRnLVfFE0tg/K8p9SvxFIt/3Bj1Mka5StouB6g/F6ag6YhEoKFLy
fvKh9UjgHOtr3hFFAkBY+/0mdJHVoHSNBySk9Jwd/0jprEysx1EH5ashwtm9FGT8
C+WII54xOulymLx/S2jvSJQ2DliNWp0+rCHsqYuK
-----END RSA PRIVATE KEY-----'''

test_pub_rsa_key = b'''-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH0jEFHRr5bMjhOrIc15XYuZNYlp
Ystj2U7LICTTx6uno/z7+xdvdQwJkjCTkNgmxyB8u8z6vn0bGT0uFzQyjZihQFGL
zcAGsBsOobqJXryHsb3hcp/WM1jtdW9fwGbMVUYVym0/YV83nG0F2ei4wzgn+ivi
Xud5/WXOogDFxzQLAgMBAAE=
-----END PUBLIC KEY-----'''


class TestSMTPClient(object):
    def __init__(self):
        self.sent_mail = []

    def send_mail(self, *args, **kwargs):
        self.sent_mail.append((args, kwargs))


def new_backend():
    try:
        remove('elections.db')
    except FileNotFoundError:
        pass
    return Backend((test_priv_rsa_key, test_pub_rsa_key), TestSMTPClient(), db_url='sqlite:///elections.db')


class BackendTests(unittest.TestCase):
    def test_account_creation(self):
        backend = new_backend()
        backend.add_account('bob', 'SuperSecurePassword1234')
        acc = backend.get_account('bob')
        self.assertEqual(acc.username, 'bob')

    def test_login(self):
        backend = new_backend()
        username = 'bob'
        password = 'SuperSecurePassword1234'
        backend.add_account(username, password)

        with self.assertRaises(UnauthorisedException):
            backend.login('bob', 'WrongPassword')

        with self.assertRaises(AccountNotFoundException):
            backend.login('billy', 'NotRealPassword')

        token = backend.login(username, password)
        self.assertEqual(backend.get_account('bob'), backend.get_account_from_token(token))

    def test_duplicate_account_creation(self):
        backend = new_backend()
        backend.add_account('billy', 'SuperSecurePsswd')
        with self.assertRaises(AccountExistsException):
            backend.add_account('billy', 'DifferentPassword')

    def test_token_expiration(self):
        backend = new_backend()
        username = 'bob'
        password = 'SecurePassword'
        backend.add_account(username, password)

        token = backend.login(username, password, time_till_exp=-10)
        with self.assertRaises(InvalidTokenError):
            backend.get_account_from_token(token)

    def test_token_revocation(self):
        backend = new_backend()
        username = 'bob'
        password = 'SecurePasswrd'
        backend.add_account(username, password)

        token = backend.login(username, password)

        backend.revoke_tokens(backend.get_account(username))

        with self.assertRaises(InvalidTokenError):
            backend.get_account_from_token(token)
