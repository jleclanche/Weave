#!/bin/sh
#
# Run this file on a fresh version control checkout to setup the build
# files.

aclocal
autoconf
autoheader
automake -a
