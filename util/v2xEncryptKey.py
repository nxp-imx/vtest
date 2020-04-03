# SPDX-License-Identifier: BSD-3-Clause

# Performs AES encryption on keys with i.MX SoC Common Key Encryption Keys (KEK)
# to generate test patterns for key injection tests (vtest 11).
#
# Prerequisite: "pycryptodome" Python module must be installed.

# Copyright 2020 NXP

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
#   Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
#   Neither the name of the copyright holder nor the names of its contributors
#   may be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON  ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import sys, getopt
from Crypto.Cipher import AES

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'


def usage():

   print('v2xEncryptKey.py:')
   print('script to encrypt in AES test keys with i.MX SoC Common Key Encryption Keys (KEK)')
   print('Use the output of this tool to add a new entry for a SoC in test_common_kek_patterns[]')
   print('in vtest/src/se/SEkeyinjection.c:')
   print('')
   print('Prerequisite: "pycryptodome" Python module must be installed.')
   print('')
   print('Usage:')
   print('        v2xEncryptKey.py -k <KEK>')
   print('')
   print('  ' + color.BOLD + '-k, --kek' + color.END + '=KEK')
   print('              KEK Key Encryption Key to be used')
   print('              ' + color.BOLD + '  qxp_common ' + color.END + " i.MX8 QXP Common KEK")
   print('              ' + color.BOLD + '  dxl_common ' + color.END + " i.MX8 DXL Common KEK")
   print('')


def do_encrypt(encryptedKey, tag):

    print(color.BLUE + "/* CT Length: " + str(len(encryptedKey)) + " */" + color.END)

    print(hex(encryptedKey[0]) + ", "
            + hex(encryptedKey[1]) + ", "
            + hex(encryptedKey[2]) + ", "
            + hex(encryptedKey[3]) + ", "
            + hex(encryptedKey[4]) + ", "
            + hex(encryptedKey[5]) + ", "
            + hex(encryptedKey[6]) + ", "
            + hex(encryptedKey[7]) + ", "
            )

    print(hex(encryptedKey[8]) + ", "
            + hex(encryptedKey[9]) + ", "
            + hex(encryptedKey[10]) + ", "
            + hex(encryptedKey[11]) + ", "
            + hex(encryptedKey[12]) + ", "
            + hex(encryptedKey[13]) + ", "
            + hex(encryptedKey[14]) + ", "
            + hex(encryptedKey[15]) + ", "
            )

    print(hex(encryptedKey[16]) + ", "
            + hex(encryptedKey[17]) + ", "
            + hex(encryptedKey[18]) + ", "
            + hex(encryptedKey[19]) + ", "
            + hex(encryptedKey[20]) + ", "
            + hex(encryptedKey[21]) + ", "
            + hex(encryptedKey[22]) + ", "
            + hex(encryptedKey[23]) + ", "
            )

    print(hex(encryptedKey[24]) + ", "
            + hex(encryptedKey[25]) + ", "
            + hex(encryptedKey[26]) + ", "
            + hex(encryptedKey[27]) + ", "
            + hex(encryptedKey[28]) + ", "
            + hex(encryptedKey[29]) + ", "
            + hex(encryptedKey[30]) + ", "
            + hex(encryptedKey[31]) + ", "
            )

    print(color.BLUE + "/* Tag Length: " + str(len(tag)) + " */" + color.END)
    print(hex(tag[0]) + ", "
            + hex(tag[1]) + ", "
            + hex(tag[2]) + ", "
            + hex(tag[3]) + ", "
            + hex(tag[4]) + ", "
            + hex(tag[5]) + ", "
            + hex(tag[6]) + ", "
            + hex(tag[7]) + ", "
            )

    print(hex(tag[8]) + ", "
            + hex(tag[9]) + ", "
            + hex(tag[10]) + ", "
            + hex(tag[11]) + ", "
            + hex(tag[12]) + ", "
            + hex(tag[13]) + ", "
            + hex(tag[14]) + ", "
            + hex(tag[15]) + ", "
            )


def main(argv):

   arg_kek = ''              ''' mandatory: must be received as input '''

   try:
      opts, args = getopt.getopt(argv,"hk:",["kek="])
   except getopt.GetoptError:
      usage()
      sys.exit(1)
   for opt, arg in opts:
      if opt == '-h':
          usage();
          sys.exit()
      elif opt in ("-k", "--kek"):
         arg_kek = arg

   ''' -k, --kek is a mandatory option '''
   if arg_kek == 'qxp_common':
      kek = b'\x10\x2b\xcb\xe5\x4d\xd7\xb2\x33\x94\x6a\xd9\xb0\xa8\x54\x27\xaf\xd5\x16\xf1\x8e\x6e\xa4\xf7\x4b\xb8\x35\x1c\x37\x26\x48\xc7\xfe'
   elif arg_kek == 'dxl_common':
      kek = b'\xda\xec\x80\xc0\x0b\xbb\x02\xba\xc8\x23\x1f\x72\x40\x54\x5c\x5e\xa4\xa8\x1d\xd9\x7d\x66\x68\xf0\x4e\x64\x41\xe1\xb1\x93\x72\x8f'
   else:
      print(color.RED + 'ERROR' + color.END + ': Undefined KEK!\n')
      usage();
      sys.exit(2)

   ''' Launch the key encryption for both test keys with the chosen common KEK'''
   iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B'

   print(color.UNDERLINE)
   print("encryptedKey1:" + color.END + " (with " + arg_kek + " KEK)")
   encryptInstance = AES.new(kek, AES.MODE_GCM, nonce=iv, mac_len=16)
   encryptedKey1, tag1 = encryptInstance.encrypt_and_digest(b'\x5d\xc4\x91\xfa\x8b\xd7\xbe\x62\xaa\x83\xa4\x2e\xf1\x1d\x80\xd8\x47\x2c\x5d\xe1\xbb\x76\x72\xef\x5d\x54\x10\xb2\x17\xd5\x8f\x78')
   do_encrypt(encryptedKey1, tag1)

   print(color.UNDERLINE)
   print("encryptedKey2:" + color.END + " (with " + arg_kek + " KEK)")
   encryptInstance = AES.new(kek, AES.MODE_GCM, nonce=iv, mac_len=16)
   encryptedKey2, tag2 = encryptInstance.encrypt_and_digest(b'\x59\xb2\x30\xa0\x94\xee\xc2\x38\x49\xd5\x53\xce\xe6\xbe\xc5\x0f\x3a\x82\xd2\xa2\x1d\x9f\xf4\x7a\x6b\x43\x51\xe1\xdd\x38\x35\x8c')

   do_encrypt(encryptedKey2, tag2)

if __name__ == "__main__":

   main(sys.argv[1:])


