import os 
from setuptools import setup, find_packages


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="flask-secretbox-session",
    version="0.1.0",
    author="Peter Parkanyi",
    author_email="me@rhapsodhy.hu",
    description="Flask client side session serializer, using Sodium SecretBox authenticated encryption",
    license="BSD",
    keywords="Flask session API NaCl libsodium",
    url="https://github.com/rsdy/flask-secretbox-session",
    packages=find_packages(),
    long_description=read('README.md'),
    install_requires=["flask","pysodium"],
    classifiers=["Development Status :: 4 - Beta",
                 "License :: OSI Approved :: BSD License",
                 "Topic :: Security :: Cryptography",
                 "Topic :: Security"],
)
