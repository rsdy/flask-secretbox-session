"""
Copyright (c) 2015, Peter Parkanyi
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from base64 import urlsafe_b64decode
from pysodium import crypto_secretbox_KEYBYTES, crypto_secretbox_NONCEBYTES, crypto_secretbox, crypto_secretbox_open, crypto_generichash, randombytes
import unittest

import secretbox_session

SESSION = {'a': 'b'}
class MockApp(object):
    secret_key="asdfghjklqwertyuiop"
app = MockApp()

class TestSerializer(unittest.TestCase):
    def setUp(self):
        self.obj = secretbox_session.SecretboxTimedSerializer(app)

    def load_expect_exception(self, input):
        with self.assertRaises(Exception):
            self.obj.loads(input)
            self.fail('Loading invalid data should raise an exception!')

    def test_basic(self):
        enc = self.obj.dumps(SESSION)
        assert enc != None
        assert enc != SESSION
        assert SESSION == self.obj.loads(enc)

    def test_destructure_decrypt_decode_verbose(self):
        """
        Strictly verify the content and behaviour of the serializer,
        and how the encryption functions are used.
        """
        encrypted = self.obj.dumps(SESSION).encode('utf-8')

        dec = urlsafe_b64decode(encrypted)
        key = crypto_generichash(app.secret_key, outlen=crypto_secretbox_KEYBYTES)
        n = dec[:crypto_secretbox_NONCEBYTES]
        c = dec[crypto_secretbox_NONCEBYTES:]
        m = crypto_secretbox_open(c, n, key)

        session = self.obj.serializer.loads(m)
        assert session[self.obj.timestamp_key]
        del session[self.obj.timestamp_key]
        assert SESSION == session

    def test_loading_invalid_data_raises_exception(self):
        # truly random by mashing keyboard
        random = b'asodifasodihfoasihf;qowieh;owqeifh;asdihfaosdhfoq;hfqowiehf;oidshfa;soidhf;oiqhewfwqe'
        self.load_expect_exception(random)
        self.load_expect_exception(None)
        self.load_expect_exception(b'')
