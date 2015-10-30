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

import datetime
import time

from base64 import urlsafe_b64encode, urlsafe_b64decode
from itsdangerous import BadPayload, SignatureExpired
from flask.sessions import TaggedJSONSerializer, SecureCookieSessionInterface
from pysodium import crypto_secretbox_KEYBYTES, crypto_secretbox_NONCEBYTES, crypto_secretbox, crypto_secretbox_open, crypto_generichash, randombytes

class SecretboxTimedSerializer(object):
    """
    Encrypts and timestamps a session using the `crypto_secretbox`
    authenticated encryption function in libsodium.
    """
    def __init__(self, app, serializer=None, timestamp_key=None):
        self.key = crypto_generichash(app.secret_key, outlen=crypto_secretbox_KEYBYTES)

        self.serializer = serializer or TaggedJSONSerializer()
        self.timestamp_key = timestamp_key or '__session_timestamp__'

    def get_timestamp(self):
        return int(time.time())

    def encrypt(self, m):
        n = randombytes(crypto_secretbox_NONCEBYTES)
        c = crypto_secretbox(m, n, self.key)
        m = n + c
        return m

    def decrypt(self, m):
        n = m[:crypto_secretbox_NONCEBYTES]
        c = m[crypto_secretbox_NONCEBYTES:]
        return crypto_secretbox_open(c, n, self.key)

    def dumps(self, session):
        """
        Serializes and encrypts `session`, and returns a base64
        encoded, unicode string.
        """
        session = session.copy()
        session[self.timestamp_key] = self.get_timestamp()

        serialized = self.serializer.dumps(session)
        encrypted = self.encrypt(serialized)
        return urlsafe_b64encode(encrypted).decode('utf-8')

    def loads(self, encrypted_session, max_age=None):
        """
        Decrypts and deserializes `encrypted_session`, and returns a dictionary.
        If `max_age` is provided, and the age of the session is older
        than `max_age` in seconds, :exc:`SignatureExpired` is raised.
        """
        decoded = urlsafe_b64decode(encrypted_session.encode('utf-8'))
        decrypted = self.decrypt(decoded)
        session = self.serializer.loads(decrypted)

        age = self.get_timestamp() - session[self.timestamp_key]
        if max_age and age > max_age:
            raise SignatureExpired(
                'Signature expired; age {} > max_age {}'.format(age, max_age),
                payload=session)

        del session[self.timestamp_key]
        return session

class SecretboxCookieSessionInterface(SecureCookieSessionInterface):
    serializer = TaggedJSONSerializer
    def get_signing_serializer(self, app):
        return SecretboxTimedSerializer(app)
