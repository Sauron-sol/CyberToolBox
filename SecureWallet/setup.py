from setuptools import setup, find_packages

setup(
    name="securewallet",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'cryptography>=3.4.7',
        'eth-account>=0.5.9',
        'web3>=5.31.3',
        'eth-hash[pycryptodome]>=0.5.1',
    ],
)
