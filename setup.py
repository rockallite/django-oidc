#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

import djangooidc

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

version = djangooidc.__version__

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    print("You probably want to also tag the version now:")
    print("  git tag -a %s -m 'version %s'" % (version, version))
    print("  git push --tags")
    sys.exit()

readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')

setup(
    name='django-oidc',
    version=version,
    description="""A Django OpenID Connect (OIDC) authentication backend""",
    long_description=readme + '\n\n' + history,
    author='Marc-Antoine Gouillart',
    author_email='marsu_pilami@msn.com',
    url='https://github.com/marcanpilami/django-oidc',
    packages=[
        'djangooidc',
    ],
    include_package_data=True,
    install_requires=[
        'django>=1.8',
        'oic>=0.9.4',
    ],
    license="Apache Software License",
    zip_safe=False,
    keywords='repo_name',
    classifiers=[
        'Environment :: Web Environment',
        'Development Status :: 5 - Production/Stable',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
    ],
)
