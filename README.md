Flask-SecretBox-Session
=======================

This is a Flask session serializer that encrypts the session using crypto_secretbox.
Flask-SecretBox-Session is a drop-in replacement for the default Flask session serializer.

Usage
-----

    from secretbox_session import SecretboxCookieSessionInterface
    app.session_interface = SecretboxCookieSessionInterface()

To override the key used for storing the timestamp for avoiding clashes with
your own session objects, you can use the `timestamp_key` named argument, like
so:

    app.session_interface = SecretboxCookieSessionInterface(timestamp_key='__timestamp')

The default value of `timestamp_key` is `'__session_timestamp__'`.

License
-------
Distributed under the [2-clause BSD](http://opensource.org/licenses/BSD-2-Clause).
