"""
Setup file for PassTheSalt.
"""

import io
import os
import re

from setuptools import find_packages, setup


def get_metadata():
    """
    Return metadata for PassTheSalt.
    """
    here = os.path.abspath(os.path.dirname(__file__))
    init_path = os.path.join(here, 'src', 'passthesalt', '__init__.py')
    readme_path = os.path.join(here, 'README.md')

    with io.open(init_path, encoding='utf-8') as f:
        about_text = f.read()

    metadata = {
        key: re.search(r'__' + key + r"__ = '(.*?)'", about_text).group(1)
        for key in (
            'title',
            'version',
            'url',
            'author',
            'author_email',
            'license',
            'description',
        )
    }
    metadata['name'] = metadata.pop('title')

    with io.open(readme_path, encoding='utf-8') as f:
        metadata['long_description'] = f.read()
        metadata['long_description_content_type'] = 'text/markdown'

    return metadata


metadata = get_metadata()

# Primary requirements
install_requires = [
    'click        ==7.*',
    'cryptography ==2.*',
    'pyperclip    ==1.*',
    'requests     ==2.*',
    'serde[ext]   ==0.8.*',
    'tabulate     ==0.8.*',
    'toml         ==0.10.*',
]
entry_points = {
    'console_scripts': ['pts=passthesalt.cli:cli', 'passthesalt=passthesalt.cli:cli']
}

setup(
    # Options
    install_requires=install_requires,
    python_requires='>=3.6',
    packages=find_packages('src'),
    entry_points=entry_points,
    package_dir={'': 'src'},
    py_modules=['passthesalt'],
    # Metadata
    download_url='{url}/archive/{version}.tar.gz'.format(**metadata),
    project_urls={'Issue Tracker': '{url}/issues'.format(**metadata)},
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation :: CPython',
    ],
    keywords='password manager pbkdf2',
    **metadata,
)
