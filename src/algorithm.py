#!/usr/bin/env python3

import fs
import getopt
import hashlib
import hmac
import json
import os
import sys

from pubkey import AsymmetricKey
from symkey import SymmetricKey

# Get script directory
PYTHON  = '/usr/bin/python3'
THIS    = os.path.realpath(os.path.abspath(__file__))
THISDIR = os.path.dirname(THIS)

# Notable constants
FILEEXT = ".asym"
FILESIG = "4s3\0\0m13".encode('utf-8')
MINSIZE = 168

# Static classes
asymmetricCryptography = AsymmetricKey()
symmetricCryptography  = SymmetricKey()

# Recursively get a list of files (as relative paths) in the input directory as their paths
def ls(input):
    # Create a list of files
    files = [ ]

    # Iterate through the input directory
    for root, directories, filenames in os.walk(input):
        # Iterate through the files in the current directory
        for filename in filenames:
            # Append the relative path of the file to the list of files
            files.append(os.path.relpath(os.path.join(root, filename), input))

    # Return the list of files
    return files

def encrypt(input, output, key, pepper, narrow, force, cleanup, samePaths, dryRun, verbose):
    # Import the public key
    asymmetricCryptography.importKey(key, True)

    # Import the pepper
    if pepper:
        with open(pepper, 'rb') as f:
            pepper = f.read()

    # Gather a list of (possibly nested) files to encrypt
    plaintextFilePaths = ls(input)

    # Iterate through the files
    for truncatedPlaintextFilePath in plaintextFilePaths:
        # Shortcut to not have to type os.path.join() every time
        plaintextFilePath = os.path.join(input, truncatedPlaintextFilePath)

        # Ignore file if it does not exist within the narrow scope filter
        if narrow and not truncatedPlaintextFilePath.startswith(narrow):
            continue

        # Determine the encrypted file name by HMAC-SHA256 hashing the file name with the pepper
        # If no pepper is provided, just SHA256 hash the file name
        # This makes sure directory information is not leaked in the encrypted output
        # The pepper prevents brute-forcing that information where it's easily guessable (so long as the pepper is secure)
        # To allow files to be updated, always use the same pepper when writing to the same directories, or else the output will be append-only
        # If the retainDir option is enabled, the pathing of the input retained (with an added file extension), so none of the above applies
        ciphertextFilePath = None
        if samePaths:
            ciphertextFilePath = os.path.join(output, truncatedPlaintextFilePath + FILEEXT)
        else:
            ciphertextFileId = None
            if pepper:
                ciphertextFileId = hmac.new(pepper, truncatedPlaintextFilePath.encode('utf-8'), hashlib.sha256).hexdigest()
            else:
                ciphertextFileId = hashlib.sha256(truncatedPlaintextFilePath.encode('utf-8')).hexdigest()
            ciphertextFilePath   = os.path.join(output, ciphertextFileId)

        # Show the major operation being performed
        if verbose:
            print("Encrypting file: " + ciphertextFilePath + " <- " + plaintextFilePath)

        # Check if file already exists
        if os.path.exists(ciphertextFilePath):
            # Check if the file should be overwritten
            if force:
                # Overwrite the file
                if verbose:
                    print("Warning: Overwriting file: " + ciphertextFilePath)
            else:
                # Skip the file
                if verbose:
                    print("Warning: Skipping file: " + ciphertextFilePath)
                continue

        # Skip the actual encryption if this is a dry run
        if dryRun:
            continue

        # Generate a new AES-256-EAX symmetric key that will be used to encrypt the file and its metadata, and encrypt it using the user provided asymmetric key
        symkey             = symmetricCryptography.generate()
        encryptedSymkey    = bytes(asymmetricCryptography.encrypt(symkey))
        encryptedSymkeyLen = len(encryptedSymkey).to_bytes(32, byteorder = 'big')

        # Generate a HMAC-SHA256 hash of the encryption symmetric key using the pepper, or if not provided, just SHA256 hash it
        encryptedSymkeySig = None
        if pepper:
            encryptedSymkeySig = hmac.new(pepper, encryptedSymkey, hashlib.sha256).digest()
        else:
            encryptedSymkeySig = hashlib.sha256(encryptedSymkey).digest()

        # Gather the file's metadata (relative path, date modified, permissions, etc.) and format it in a JSON structure, then encrypt it using the symmetric key just created
        metadata = {
            'path':  truncatedPlaintextFilePath,
            'mtime': os.stat(os.path.join(input, truncatedPlaintextFilePath)).st_mtime,
            'uid':   os.stat(os.path.join(input, truncatedPlaintextFilePath)).st_uid,
            'gid':   os.stat(os.path.join(input, truncatedPlaintextFilePath)).st_gid,
            'mode':  os.stat(os.path.join(input, truncatedPlaintextFilePath)).st_mode
        }
        metadata             = json.dumps(metadata).encode('utf-8')
        encryptedMetadata    = bytes(symmetricCryptography.encrypt(metadata))
        encryptedMetadataLen = len(encryptedMetadata).to_bytes(32, byteorder = 'big')

        # Generate a HMAC-SHA256 hash of the encrypted metadata using the pepper, or if not provided, just SHA256 hash it
        encryptedMetadataSig = None
        if pepper:
            encryptedMetadataSig = hmac.new(pepper, encryptedMetadata, hashlib.sha256).digest()
        else:
            encryptedMetadataSig = hashlib.sha256(encryptedMetadata).digest()
        
        # Encrypt the plaintext file itself using the symmetric key
        encryptedData = None
        with open(plaintextFilePath, 'rb') as data:
            encryptedData = bytes(symmetricCryptography.encrypt(data.read()))

        # Generate a HMAC-SHA256 hash of the encrypted data using the pepper, or if not provided, just SHA256 hash it
        encryptedDataSig = None
        if pepper:
            encryptedDataSig = hmac.new(pepper, encryptedData, hashlib.sha256).digest()
        else:
            encryptedDataSig = hashlib.sha256(encryptedData).digest()

        # Combine the results of the previous steps into a single file
        # The resulting file is structured as follows:
        #   - 8 bytes:  filetype signature (constant)
        #   - 32 bytes: encrypted symmetric key (HMAC-)SHA-256 signature
        #   - 32 bytes: encrypted symmetric key length
        #   - N bytes:  encrypted symmetric key
        #   - 32 bytes: encrypted metadata (HMAC-)SHA-256 signature
        #   - 32 bytes: encrypted metadata length
        #   - N bytes:  encrypted metadata
        #   - 32 bytes: encrypted data (HMAC-)SHA-256 signature
        #   - N bytes:  encrypted data
        ciphertext = FILESIG + encryptedSymkeySig + encryptedSymkeyLen + encryptedSymkey + encryptedMetadataSig + encryptedMetadataLen + encryptedMetadata + encryptedDataSig + encryptedData

        # Write the file to disk
        if samePaths:
            ciphertextFileDir = os.path.dirname(ciphertextFilePath)
            if not os.path.exists(ciphertextFileDir):
                os.makedirs(ciphertextFileDir)
        with open(ciphertextFilePath + ".tmp", 'wb') as cf:
            cf.write(ciphertext)
        
        # Overwrite the old file with the new file, if it already exists
        if os.path.exists(ciphertextFilePath):
            os.remove(ciphertextFilePath)
        
        # Rename the temporary file to the actual file
        os.rename(ciphertextFilePath + ".tmp", ciphertextFilePath)

        # If cleanup is enabled, delete the plaintext file (after zero-filling it)
        if cleanup:
            with open(plaintextFilePath, 'wb') as f:
                f.write(b'\0' * os.path.getsize(plaintextFilePath))
            os.remove(plaintextFilePath)

def decrypt(input, output, key, passFile, pepper, narrow, force, cleanup, dryRun, verbose):
    # Track the number of failed files
    failed = 0

    # Import the private key
    asymmetricCryptography.importKey(key, False, passFile)

    # Import the pepper
    if pepper:
        with open(pepper, 'rb') as f:
            pepper = f.read()

    # Gather a list of (possibly nested) files to encrypt
    ciphertextFilePaths = ls(input)

    # Iterate through the files
    for ciphertextFilePath in ciphertextFilePaths:
        # Shortcut to not have to type os.path.join() every time
        ciphertextFilePath = os.path.join(input, ciphertextFilePath)

        # Show the major operation being performed
        if verbose:
            print("File located: " + ciphertextFilePath)

        # Reject the file if it is too small
        # In reality, the given number of bytes is still too small, due to variable length fields not being included in the amount
        # However, it's a good enough heuristic (and optimization) to prevent the program from crashing
        # This will at least assure there's enough bytes to read the file signature
        if os.path.getsize(ciphertextFilePath) <= MINSIZE:
            print("Warning: File rejected: \"" + ciphertextFilePath + "\" is less than the minimum-required size.")
            continue

        # Read the file
        ciphertext = None
        with open(ciphertextFilePath, 'rb') as cf:
            ciphertext = cf.read()

        # Verify the file signature
        if ciphertext[0:len(FILESIG)] != FILESIG:
            print("Warning: File rejected: \"" + ciphertextFilePath + "\" lacks the necessary signature.")
            continue

        # Offset to manage the current context
        offset = len(FILESIG)

        # Read the length of the encrypted symmetric key
        encryptedSymkeyLen = int.from_bytes(ciphertext[(offset + 32):(offset + 64)], byteorder = 'big')

        # Attempt to decrypt the encrypted symmetric key
        encryptedSymkey = ciphertext[(offset + 64):(offset + 64 + encryptedSymkeyLen)]
        symkey          = None
        try:
            symkey = asymmetricCryptography.decrypt(encryptedSymkey)
        except:
            print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".")
            failed += 1
            continue
        
        # Parse the symmetric key
        symmetricCryptography.importKey(symkey)
        
        # Verify the encrypted symmetric key signature
        encryptedSymkeySig = ciphertext[offset:(offset + 32)]
        if pepper:
            if hmac.new(pepper, encryptedSymkey, hashlib.sha256).digest() != encryptedSymkeySig:
                print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".")
                failed += 1
                continue
        else:
            if hashlib.sha256(encryptedSymkey).digest() != encryptedSymkeySig:
                print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".")
                failed += 1
                continue
        
        # Raise the offset for the metadata
        offset += 64 + encryptedSymkeyLen
        
        # Read the length of the encrypted metadata
        encryptedMetadataLen = int.from_bytes(ciphertext[(offset + 32):(offset + 64)], byteorder = 'big')

        # Attempt to decrypt the encrypted metadata
        encryptedMetadata = ciphertext[(offset + 64):(offset + 64 + encryptedMetadataLen)]
        metadata          = None
        try:
            metadata = symmetricCryptography.decrypt(encryptedMetadata)
        except:
            print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".")
            failed += 1
            continue
        
        # Verify the encrypted metadata signature
        encryptedMetadataSig = ciphertext[offset:(offset + 32)]
        if pepper:
            if hmac.new(pepper, encryptedMetadata, hashlib.sha256).digest() != encryptedMetadataSig:
                print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".")
                failed += 1
                continue
        else:
            if hashlib.sha256(encryptedMetadata).digest() != encryptedMetadataSig:
                print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".")
                failed += 1
                continue
        
        # Parse the metadata
        metadata = json.loads(metadata.decode('utf-8'))
        
        # Get the path of the plaintext file
        truncatedPlaintextFilePath = metadata['path']
        plaintextFilePath          = os.path.join(output, truncatedPlaintextFilePath)
        
        # Ignore file if it does not exist within the narrow scope filter
        if narrow and not truncatedPlaintextFilePath.startswith(narrow):
            continue

        # Show the major operation being performed
        if verbose:
            print("Decrypting file: " + ciphertextFilePath + " -> " + plaintextFilePath)

        # Check if file already exists
        if os.path.exists(plaintextFilePath):
            # Check if the file should be overwritten
            if force:
                # Overwrite the file
                if verbose:
                    print("Warning: Overwriting file: " + plaintextFilePath)
            else:
                # Skip the file
                if verbose:
                    print("Warning: Skipping file: " + plaintextFilePath)
                continue

        # Skip the actual decryption if this is a dry run
        if dryRun:
            continue
        
        # Raise the offset for the data
        offset += 64 + encryptedMetadataLen

        # Attempt to decrypt the encrypted data
        encryptedData = ciphertext[(offset + 32):]
        data          = None
        try:
            data = symmetricCryptography.decrypt(encryptedData)
        except:
            print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".")
            failed += 1
            continue
        
        # Verify the encrypted data signature
        encryptedDataSig = ciphertext[offset:(offset + 32)]
        if pepper:
            if hmac.new(pepper, encryptedData, hashlib.sha256).digest() != encryptedDataSig:
                print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".")
                failed += 1
                continue
        else:
            if hashlib.sha256(encryptedData).digest() != encryptedDataSig:
                print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".")
                failed += 1
                continue
        
        # Attempt to write the file to the path stored in the metadata
        plaintextFileDir = os.path.dirname(plaintextFilePath)
        if not os.path.exists(plaintextFileDir):
            os.makedirs(plaintextFileDir)
        with open(plaintextFilePath + ".tmp", 'wb') as pf:
            pf.write(data)
        
        # Overwrite the old file with the new file, if it already exists
        if os.path.exists(plaintextFilePath):
            os.remove(plaintextFilePath)
        
        # Rename the temporary file to the actual file
        os.rename(plaintextFilePath + ".tmp", plaintextFilePath)

        # Set the file's other metadata
        os.utime(plaintextFilePath, (metadata['mtime'], metadata['mtime']))
        os.chown(plaintextFilePath, metadata['uid'], metadata['gid'])
        os.chmod(plaintextFilePath, metadata['mode'])

        # If cleanup is enabled, delete the ciphertext file
        if cleanup:
            os.remove(ciphertextFilePath)
            
    # Print the number of failed files
    if failed > 0:
        print("Error: Failed to decrypt " + str(failed) + " file(s)!")
        sys.exit(2)
