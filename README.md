[![Build Status](https://travis-ci.org/ereOn/csodium.svg?branch=master)](https://travis-ci.org/ereOn/csodium)
[![Coverage Status](https://coveralls.io/repos/ereOn/csodium/badge.svg?branch=master&service=github)](https://coveralls.io/github/ereOn/csodium?branch=master)
[![Documentation Status](https://readthedocs.org/projects/csodium/badge/?version=latest)](http://csodium.readthedocs.org/en/latest/?badge=latest)
[![PyPI](https://img.shields.io/pypi/pyversions/csodium.svg)](https://pypi.python.org/pypi/csodium/1.0.0)
[![PyPi version](https://img.shields.io/pypi/v/csodium.svg)](https://pypi.python.org/pypi/csodium/1.0.0)
[![PyPi downloads](https://img.shields.io/pypi/dm/csodium.svg)](https://pypi.python.org/pypi/csodium/1.0.0)

# csodium

**csodium** is a Python 2/3 standalone interface for `libsodium`.

## Rationale

`csodium` was started as the result of a
[disagreement](https://github.com/stef/pysodium/issues/45) with `pysodium`
maintainers. They wanted the library to remain a simple wrapper (using `ctypes`
to dynamically load `libsodium` at runtime, mainly to always use the latest
system available `libsodium`) while we wanted it to be a standalone package
that would work out of the box, especially for Windows/Mac OSX wheel users.

The goal being users should not need to install/compile `libsodium` and could
just do `pip install` to get things started.

Another point of conflict is the [support of Python
3](https://github.com/stef/pysodium/issues/2).

As an attempt to make the best out of those two opinions, `csodium` was
initiated, which aims at providing an out-of-the-box, ready-to-use `libsodium`
Python interface while still giving the ability to Linux and OSX users to
recompile and/or use the latest available `libsodium` if they want to.

`csodium` aims to be compatible with `pysodium`, but there is **no syncing** of
any kind between the two projects as of now, so their APIs might diverge in the
future.

## API

`csodium` aims at offering the whole `libsodium` API through its Python's
bindings. However, it only offers a subset at the moment (`crypto_box` and
`crypto_secretbox` family functions). I'm the sole contributor which explains
why this API support improves slowly. If you are interested in making things
faster, adding new functions is actually really simple and pull requests are
most welcome ! Here is the guide:

1. Find the exact `C` prototype of the function you wish to add support for and
   add it to the `_build.py` module.
2. Implement a meaningful Python version of that function in the `__init__.py`
   module. You can get your inspiration from already defined function.
3. Make sure you handle well incorrect input value and that you raise
   appropriately on errors. See the `_raise_on_error` helper function.
4. Write tests that cover input failures as well as at least a successful run.
   Coverage should remain at 100%. Also remember that the goal is not to test
   `libsodium` but the Python binding.
5. Submit your pull request !

## Python 2 support on Windows

Sadly, `libsodium` hasn't been supporting Visual Studio 2008 for a while and
this is required to make binary packages for Python 2.7 on Windows. If you know
of a simple way to compile `libsodium` using *Visual Studio for Python* that
doesn't prevent upgrading `libsodium`, please contribute !

## Installation

You may install it by using `pip`:

> pip install csodium
