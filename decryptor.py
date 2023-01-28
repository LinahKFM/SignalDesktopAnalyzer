"""Decrypts SQLite databases and temporary WAL files encrypted with SQLCipher4.

- This module is part of SignalDesktopAnalyzer add-on ingest module for Autopsy.
- Written in Jython.

Functions:
    decryptDB(str, str, str)
    wrapAround(long) -> long
    checksum(bytes, long, long) -> long, long
    decryptWAL(str, str, str, boolean)

"""
from java.lang import Long
from java.nio import ByteBuffer
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec
from javax.crypto.spec import SecretKeySpec

import os


def decryptDB(key, pathToDB, pathToDecryptedDB):
    """Decrypts SQLite database encrypted with SQLCipher4.
    
    - Details about SQLCipher4 can be found @ https://www.zetetic.net/sqlcipher/design/
    - Details about SQLite file format can be found @ https://www.sqlite.org/fileformat2.html
    - pysqlsimplecipher available @ https://github.com/bssthu/pysqlsimplecipher was used for reference.

    Args:
        key (string): the decryption key in hex.
        pathToDB (string): the path of the encrypted SQLite database file.
        pathToDecryptedDB (string): the path the database file is stored at after decryption.
        """

    # Decryption defaults
    PAGE_SIZE = 4096
    SALT_SIZE = 16
    IV_SIZE = 16
    HMAC_SIZE = 64
    RESERVED_SIZE = IV_SIZE + HMAC_SIZE

    file_size = os.path.getsize(pathToDB)

    with open(pathToDB,'rb') as fin:
        with open(pathToDecryptedDB,'wb') as fout:
                
            # Write SQLite's magic header string
            fout.write(b'SQLite format 3\0')
                
            # Process every page in the file
            for i in range(int(file_size / PAGE_SIZE)):
                page = fin.read(PAGE_SIZE)
                # Ignore the salt in the first page
                if i == 0:
                    page = page[SALT_SIZE:]
                # Copy the iv
                iv = page[-RESERVED_SIZE:-HMAC_SIZE]
                # Store page content without the reserved bytes 
                page_content = page[:-RESERVED_SIZE]
                # Decrypt
                cipher = Cipher.getInstance("AES/CBC/NOPADDING")
                cipher.init(Cipher.DECRYPT_MODE,
                            SecretKeySpec(bytes(bytearray.fromhex(key)), "AES"),
                            IvParameterSpec(bytes(iv)))
                plaintext = cipher.doFinal(page_content)

                fout.write(plaintext)
                # Fill up the reserved space with zeros to preserve the file format
                fout.write(bytearray(RESERVED_SIZE))


def wrapAround(x):
    """Interprets a potentially long number as an unsigned int.

    Args:
        x (long): a 64-bit number.

    Returns:
        x (long): a 64-bit number that has the most significant 32 bits as zeros
                  and the least significant 32 bits taken from the argument x.
        """
        
    # If larger than the maximum unsigned int value
    if x > 4294967295:
        # only keep the least-significant 32 bits
        x = x & 0xFFFFFFFF
    return x


def checksum(data, s0, s1):
    """Calculates WAL frame checksum.

    This function re-implements the checksum function of SQLite 
    available @ https://sqlite.org/src/file/src/wal.c with the name walChecksumBytes.

    Args:
        data (bytes): The data to be checksummed.
        s0 (long): The first part of the chacksum. Initially 0, then stores the cumulative value.
        s1 (long): The second part of the checksum. Initially 0, then stores the cumulative value.

    Returns:
        s0 (long): The first part of the cumulative chacksum.
        s1 (long): The second part of the cumulative checksum.
    """
        
    integers = []
    # Parse data as 32bit unsigned integers
    j=0
    for i in range(1, (len(data) / 4) + 1):

        x = data.encode("hex")[j:i*8]
        # Swap to little endian
        littleX = ""
        for i in range(4):
            littleX += x[-2:]
            x = x[:-2]
        longX = Long.parseLong(littleX, 16)
        # Add number to the list of integers after ensuring it is represented in 32 bits
        integers.append(wrapAround(longX))
        j+=8

    # Perform SQLite's cumulative checksum algorithm
    for i in range(0, len(integers) - 1, 2):
        s0 += integers[i] + s1
        s1 += integers[i+1] + s0

    return s0, s1


def decryptWAL(key, pathToWal, pathToDecryptedWal, doChecksum):
    """Decrypts SQLite WAL files encrypted with SQLCipher4 and optionally recalculates WAL frames checksums.

    - Details about WAL file format can be found @ https://www.sqlite.org/fileformat2.html#walformat
    - pysqlsimplecipher available @ https://github.com/bssthu/pysqlsimplecipher was used for reference.
        
    Args:
        key (string): the decryption key in hex.
        pathToWal (string): the path of the encrypted SQLite wal file.
        pathToDecryptedWal (string): the path the wal file is stored at after decryption.
        doChecksum (boolean): Recalculates checksum if set to true.
    """
    
    # Decryption and WAL header defaults
    PAGE_SIZE = 4096
    IV_SIZE = 16
    HMAC_SIZE = 64
    RESERVED_SIZE = IV_SIZE + HMAC_SIZE
    WAL_HEADER_SIZE = 32
    FRAME_HEADER_SIZE = 24
    file_size = os.path.getsize(pathToWal)

    with open(pathToWal,'rb') as fin:
        with open(pathToDecryptedWal,'wb') as fout:

            wal_header = fin.read(WAL_HEADER_SIZE)

            if doChecksum:
                # Checksum the wal file header with s0 and s1 initially as zeros
                s0, s1 = checksum(wal_header[:24], s0 = 0, s1 = 0)
                # Convert s0 and s1 from long to bytes and ignore the most significant 4 bytes
                checksum0 = bytearray(ByteBuffer.allocate(8).putLong(wrapAround(s0)).array())[4:]
                checksum1 = bytearray(ByteBuffer.allocate(8).putLong(wrapAround(s1)).array())[4:]
                # Create new wal file header with updated checksum values
                wal_header = wal_header[:24] + checksum0 + checksum1

            fout.write(wal_header)
            file_size -= WAL_HEADER_SIZE

            # Process every page in the file with its frame header
            for i in range(int(file_size/(FRAME_HEADER_SIZE + PAGE_SIZE))):
                frame_header = fin.read(FRAME_HEADER_SIZE)
                page = fin.read(PAGE_SIZE)
                # Copy the iv
                iv = page[-RESERVED_SIZE:-HMAC_SIZE]
                # Store page content without the reserved bytes 
                page_content = page[:-RESERVED_SIZE]
                cipher = Cipher.getInstance("AES/CBC/NOPADDING")
                cipher.init(Cipher.DECRYPT_MODE,
                            SecretKeySpec(bytes(bytearray.fromhex(key)), "AES"),
                            IvParameterSpec(bytes(iv)))

                if doChecksum:
                    plaintext = bytearray(cipher.doFinal(page))
                    # Checksum data including the first 8 bytes of the frame header
                    # and the decrypted page
                    s0, s1 = checksum(frame_header[:8] + plaintext, s0, s1)
                    # Convert s0 and s1 from long to bytes and ignore the most significant 4 bytes
                    checksum0 = bytearray(ByteBuffer.allocate(8).putLong(wrapAround(s0)).array())[4:]
                    checksum1 = bytearray(ByteBuffer.allocate(8).putLong(wrapAround(s1)).array())[4:]
                    # Create new frame header with updated checksum values
                    frame_header = frame_header[:8] + wal_header[16:24] + checksum0 + checksum1
                    fout.write(frame_header)
                    fout.write(plaintext)
                else:
                    plaintext = cipher.doFinal(page_content)
                    fout.write(frame_header)
                    fout.write(plaintext)
                    # Fill up the reserved space with zeros to preserve the file format
                    fout.write(bytearray(RESERVED_SIZE))
    