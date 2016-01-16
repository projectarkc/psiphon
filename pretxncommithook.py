#!/usr/bin/python
#
# Copyright (c) 2012, Psiphon Inc.
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# To use, add these lines to your .hg/hgrc file:
#  [hooks]
#  pretxncommit = python pretxncommithook.py


import sys
import os

def no_embedded_values(difflines):
    '''
    Ensure that the "embedded values" file(s) are not included in the commit.
    Returns true if no embedded values file is found (i.e., the commit can
    proceed).
    '''
    for line in difflines:
        line = line.strip()
        if line.startswith('diff ') and line.endswith('EmbeddedValues.java'):
            print >> sys.stderr, 'EmbeddedValues.java commit disallowed!'
            return False
        if line.startswith('diff ') and line.endswith('embeddedvalues.h'):
            print >> sys.stderr, 'embeddedvalues.h commit disallowed!'
            return False
    return True

if __name__ == '__main__':

    if not no_embedded_values(os.popen('hg export tip')):
        sys.exit(1)

    sys.exit(0)
