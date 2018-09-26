import io
import os
import re

from setuptools import setup


def read(*path):
    """
    Cross-platform Python 2/3 file reading.
    """
    filename = os.path.join(os.path.dirname(__file__), *path)
    with io.open(filename, encoding='utf8') as f:
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

install_requirements = [
    'click>=7.0',
    'cryptography>=2.0.0',
    'pyperclip>=1.0.0',
    'tabulate>=0.5.0'
]

lint_requirements = [
    'flake8',
    'flake8-docstrings',
    'flake8-isort',
    'flake8-per-file-ignores',
    'flake8-quotes',
    'mccabe',
    'pep8-naming'
]

test_requirements = [
    'pytest',
    'pytest-cov'
]

package_requirements = [
    'twine'
]

entry_points = {
    'console_scripts': [
        'pts=passthesalt.cli:cli',
        'passthesalt=passthesalt.cli:cli'
    ]
}

setup(
    name='passthesalt',
    packages=['passthesalt'],
    version=version,
    install_requires=install_requirements,
    extras_require={'linting': lint_requirements,
                    'testing': test_requirements,
                    'packaging': package_requirements},
    python_requires='>=3.4',
    entry_points=entry_points,

    author='Ross MacArthur',
    author_email='macarthur.ross@gmail.com',
    description='Deterministic password generation and password storage.',
    long_description=long_description,
    license='MIT',
    keywords='password manager pbkdf2',
    url='https://github.com/rossmacarthur/passthesalt',
    download_url='https://github.com/rossmacarthur/passthesalt/archive/{version}.tar.gz'
                 .format(version=version),
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ]
)
