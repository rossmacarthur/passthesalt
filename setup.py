from setuptools import setup

install_requirements = [
    'click==6.7',
    'pycrypto==2.6.1',
    'pyperclip==1.5.27'
]

setup(
    name='passthesalt',
    author='Ross MacArthur',
    author_email='macarthur.ross@gmail.com',
    version='0.0.1',
    description='A deterministic password generation and password storage system.',
    url='https://github.com/rossmacarthur/passthesalt',
    install_requires=install_requirements,
    entry_points={
        'console_scripts': [
            'pts=passthesalt.__main__:cli',
            'passthesalt=passthesalt.__main__:cli'
        ]
    }
)
