import io
import os
import re
from setuptools import setup


def read(*path):
    """
    Python 2/3 file reading.
    """
    version_file = os.path.join(os.path.dirname(__file__), *path)
    with io.open(version_file, encoding='utf8') as f:
        return f.read()


def find_version():
    """
    Regex search __init__.py so that we do not have to import.
    """
    text = read('passthesalt', '__init__.py')
    match = re.search(r'^__version__ = [\'"]([^\'"]*)[\'"]', text, re.M)
    if match:
        return match.group(1)
    raise RuntimeError('Unable to find version string.')


version = find_version()

long_description = read('README.rst')

install_requires = [
    'click==6.7',
    'pycrypto==2.6.1',
    'pyperclip==1.5.27'
]

entry_points = {
    'console_scripts': [
        'passthesalt=passthesalt.__main__:cli',
        'pts=passthesalt.__main__:cli'
    ]
}

setup(
    name='passthesalt',
    packages=['passthesalt'],
    version=version,
    install_requires=install_requires,
    entry_points=entry_points,
    python_requires='>=3',
    description='A deterministic password generation and password storage system.',
    long_description=long_description,
    author='Ross MacArthur',
    author_email='macarthur.ross@gmail.com',
    license='MIT',
    url='https://github.com/rossmacarthur/passthesalt',
    download_url='https://github.com/rossmacarthur/passthesalt/archive/{}.tar.gz'.format(version),
    keywords='password manager pbkdf2',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only'
    ]
)
