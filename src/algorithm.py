#!/usr/bin/env python3

import hashlib
import hmac
import json
import os
import re
import sys
from   threading import Thread

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

# Return true if the file should be included, false otherwise, based on order of presented include/exclude regexes
def doInclude(filepath, patterns):
    # Default is to include if no patterns are provided
    if len(patterns) == 0:
        return True
    
    # If the starting pattern is an exclude pattern, then the default rule is to include
    # If the starting pattern is an include pattern, then the default rule is to exclude
    if patterns[0] == True:
        matched = False
    else:
        matched = True

    # Iterate through the patterns (necessarily through all of them always)
    i = 0
    while i < len(patterns):
        include = patterns[i]
        pattern = patterns[i + 1]

        if re.match(pattern, filepath):
            matched = include

        i += 2
    
    # Return the final answer
    return matched

# Deletes a file with the option to zero-fill it first
def deleteFile(filePath, doShred, isVerbose):
    if doShred:
        if isVerbose:
            print("Shredding file: " + filePath)
        with open(filePath, 'wb') as f:
            f.write(b'\0' * os.path.getsize(filePath))
    else:
        if isVerbose:
            print("Deleting file: " + filePath)
    os.remove(filePath)

# Writes a temporary file to disk, then renames it to the actual file
def safeWrite(filePath, data, doShred):
    with open(filePath + ".tmp", 'wb') as f:
        try:
            f.write(data)
        except:
            print("Error: Failed to write \"" + filePath + "\".", file = sys.stderr)
            return False

    # Overwrite the existing file in the output if it already exists
    # This should only run after the "--force" option is checked for, so it will be skipped otherwise
    if os.path.exists(filePath):
        try:
            deleteFile(filePath, doShred, False)
        except:
            deleteFile(filePath + ".tmp", doShred, False)
            print("Error: Failed to write \"" + filePath + "\".", file = sys.stderr)
            return False
        
    return True

# Clears the input directory
# This should run after a cleanup of the files that might or might not need to be zero-filled
# Files left over are thought to be an oversight, 
def clearInput(input, isVerbose):
    failedSubdirectories = 0

    if isVerbose:
        print("Clearing input directory: " + input)

    for root, directories, filenames in os.walk(input, topdown = False):
        if len(filenames) > 0:
            print("Error: Failed to clear input directory; there are still files inside of it!", file = sys.stderr)
            sys.exit(2)

        # Normally, there should only be directories left after the normal cleanup, which should have been done already
        for directory in directories:
            try:
                os.rmdir(os.path.join(root, directory))
            except:
                print("Error: Failed to delete input sub-directory: " + os.path.join(root, directory), file = sys.stderr)
                failedSubdirectories += 1
    
    if failedSubdirectories > 0:
        sys.exit(2)

def encryptFile(truncatedPlaintextFilePath, args, secrets, stats):
    # Shortcut to not have to type os.path.join() every time
    plaintextFilePath = os.path.join(args["input"], truncatedPlaintextFilePath)

    # Ignore file if it does not pass through the include/exclude pattern filters
    if doInclude(truncatedPlaintextFilePath, args["patterns"]) == False:
        return

    # Determine the encrypted file name by HMAC-SHA256 hashing the file name with the pepper
    # If no pepper is provided, just SHA256 hash the file name
    # This makes sure directory information is not leaked in the encrypted output
    # The pepper prevents brute-forcing that information where it's easily guessable (so long as the pepper is secure)
    # To allow files to be updated, always use the same pepper when writing to the same directories, or else the output will be append-only
    # If the retainDir option is enabled, the pathing of the input retained (with an added file extension), so none of the above applies
    ciphertextFilePath = None
    if args["doSamePaths"]:
        ciphertextFilePath = os.path.join(args["output"], truncatedPlaintextFilePath)
    else:
        ciphertextFileId = None
        if secrets["pepper"]:
            ciphertextFileId = hmac.new(secrets["pepper"], truncatedPlaintextFilePath.encode('utf-8'), hashlib.sha256).hexdigest()
        else:
            ciphertextFileId = hashlib.sha256(truncatedPlaintextFilePath.encode('utf-8')).hexdigest()
        ciphertextFilePath   = os.path.join(args["output"], ciphertextFileId)

    # Add the file extension if it is enabled
    if args["doExtension"]:
        ciphertextFilePath += FILEEXT

    # Show the major operation being performed
    if args["isVerbose"]:
        print("Encrypting file: " + ciphertextFilePath + " <- " + plaintextFilePath)

    # Check if file already exists
    if os.path.exists(ciphertextFilePath):
        # Check if the file should be overwritten
        if args["doForce"]:
            # Overwrite the file
            if args["isVerbose"]:
                print("Warning: Overwriting file: " + ciphertextFilePath)
        else:
            # Skip the file
            if args["isVerbose"]:
                print("Warning: Skipping file: " + ciphertextFilePath)
            return

    # Skip the actual encryption if this is a dry run
    if args["doDryRun"]:
        return

    # Generate a new AES-256-EAX symmetric key that will be used to encrypt the file and its metadata, and encrypt it using the user provided asymmetric key
    symmetricCryptography = SymmetricKey()
    symkey                = symmetricCryptography.generate()
    encryptedSymkey       = bytes(secrets["key"].encrypt(symkey))
    encryptedSymkeyLen    = len(encryptedSymkey).to_bytes(32, byteorder = 'big')

    # Generate a HMAC-SHA256 hash of the encryption symmetric key using the pepper, or if not provided, just SHA256 hash it
    encryptedSymkeySig = None
    if secrets["pepper"]:
        encryptedSymkeySig = hmac.new(secrets["pepper"], encryptedSymkey, hashlib.sha256).digest()
    else:
        encryptedSymkeySig = hashlib.sha256(encryptedSymkey).digest()

    # Gather the file's metadata (relative path, date modified, permissions, etc.) and format it in a JSON structure, then encrypt it using the symmetric key just created
    metadata = {
        'path':  truncatedPlaintextFilePath,
        'mtime': os.stat(os.path.join(args["input"], truncatedPlaintextFilePath)).st_mtime
    }
    metadata             = json.dumps(metadata).encode('utf-8')
    encryptedMetadata    = bytes(symmetricCryptography.encrypt(metadata))
    encryptedMetadataLen = len(encryptedMetadata).to_bytes(32, byteorder = 'big')

    # Generate a HMAC-SHA256 hash of the encrypted metadata using the pepper, or if not provided, just SHA256 hash it
    encryptedMetadataSig = None
    if secrets["pepper"]:
        encryptedMetadataSig = hmac.new(secrets["pepper"], encryptedMetadata, hashlib.sha256).digest()
    else:
        encryptedMetadataSig = hashlib.sha256(encryptedMetadata).digest()
    
    # Encrypt the plaintext file itself using the symmetric key
    encryptedData = None
    with open(plaintextFilePath, 'rb') as data:
        encryptedData = bytes(symmetricCryptography.encrypt(data.read()))

    # Generate a HMAC-SHA256 hash of the encrypted data using the pepper, or if not provided, just SHA256 hash it
    encryptedDataSig = None
    if secrets["pepper"]:
        encryptedDataSig = hmac.new(secrets["pepper"], encryptedData, hashlib.sha256).digest()
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

    # Only if same-paths is enabled, you will have directories in the encrypted output
    if args["doSamePaths"]:
        ciphertextFileDir = os.path.dirname(ciphertextFilePath)
        if not os.path.exists(ciphertextFileDir):
            os.makedirs(ciphertextFileDir)
    
    # Write the file to disk
    success = safeWrite(ciphertextFilePath, ciphertext, args["doShred"])
    if success == False:
        return
    
    # Rename the temporary file to the actual file
    os.rename(ciphertextFilePath + ".tmp", ciphertextFilePath)

    # If cleanup is enabled, delete the plaintext file (after zero-filling it)
    if args["doCleanup"]:
        deleteFile(plaintextFilePath, args["doShred"], args["isVerbose"])
    
    # Increment the number of successful files
    with stats["mutex"]:
        stats["successful"] += 1

def encrypt(args, secrets, stats):
    # Import the public key
    asymmetricCryptography = AsymmetricKey()
    asymmetricCryptography.importKey(args["key"], True)
    secrets["key"] = asymmetricCryptography

    # Gather a list of (possibly nested) files to encrypt
    plaintextFilePaths = ls(args["input"])

    # Iterate through the files
    threads = [ ]
    for truncatedPlaintextFilePath in plaintextFilePaths:
        stats["total"] += 1
        thread = Thread(target = encryptFile, args = (truncatedPlaintextFilePath, args, secrets, stats))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
        
    # Delete everything in the input, directories included, if set to do so
    if args["doClearInput"]:
        clearInput(args["input"], args["isVerbose"])

def decryptFile(truncatedCiphertextFilePath, args, secrets, stats):
    # Shortcut to not have to type os.path.join() every time
    ciphertextFilePath = os.path.join(args["input"], truncatedCiphertextFilePath)

    # Show the major operation being performed
    if args["isVerbose"]:
        print("File located: " + ciphertextFilePath)

    # Reject the file if it is too small
    # In reality, the given number of bytes is still too small, due to variable length fields not being included in the amount
    # However, it's a good enough heuristic (and optimization) to prevent the program from crashing
    # This will at least assure there's enough bytes to read the file signature
    if os.path.getsize(ciphertextFilePath) <= MINSIZE:
        print("Warning: File ignored: \"" + ciphertextFilePath + "\" is less than the minimum-required size.")
        return

    # Read the file
    ciphertext = None
    with open(ciphertextFilePath, 'rb') as cf:
        ciphertext = cf.read()

    # Verify the file signature
    if ciphertext[0:len(FILESIG)] != FILESIG:
        print("Warning: File ignored: \"" + ciphertextFilePath + "\" lacks the necessary signature.")
        return

    # Offset to manage the current context
    offset = len(FILESIG)

    # Read the length of the encrypted symmetric key
    encryptedSymkeyLen = int.from_bytes(ciphertext[(offset + 32):(offset + 64)], byteorder = 'big')

    # Attempt to decrypt the encrypted symmetric key
    encryptedSymkey = ciphertext[(offset + 64):(offset + 64 + encryptedSymkeyLen)]
    symkey          = None
    try:
        symkey = secrets["key"].decrypt(encryptedSymkey)
    except:
        print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".", file = sys.stderr)
        with stats["mutex"]:
            stats["failed"] += 1
        return
    
    # Parse the symmetric key
    symmetricCryptography = SymmetricKey()
    symmetricCryptography.importKey(symkey)
    
    # Verify the encrypted symmetric key signature
    encryptedSymkeySig = ciphertext[offset:(offset + 32)]
    if secrets["pepper"]:
        if hmac.new(secrets["pepper"], encryptedSymkey, hashlib.sha256).digest() != encryptedSymkeySig:
            print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".", file = sys.stderr)
            with stats["mutex"]:
                stats["failed"] += 1
            return
    else:
        if hashlib.sha256(encryptedSymkey).digest() != encryptedSymkeySig:
            print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".", file = sys.stderr)
            with stats["mutex"]:
                stats["failed"] += 1
            return
    
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
        print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".", file = sys.stderr)
        with stats["mutex"]:
            stats["failed"] += 1
        return
    
    # Verify the encrypted metadata signature
    encryptedMetadataSig = ciphertext[offset:(offset + 32)]
    if secrets["pepper"]:
        if hmac.new(secrets["pepper"], encryptedMetadata, hashlib.sha256).digest() != encryptedMetadataSig:
            print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".", file = sys.stderr)
            with stats["mutex"]:
                stats["failed"] += 1
            return
    else:
        if hashlib.sha256(encryptedMetadata).digest() != encryptedMetadataSig:
            print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".", file = sys.stderr)
            with stats["mutex"]:
                stats["failed"] += 1
            return
    
    # Parse the metadata
    metadata = json.loads(metadata.decode('utf-8'))
    
    # Get the path of the plaintext file
    if args["doSamePaths"]:
        truncatedPlaintextFilePath = truncatedCiphertextFilePath
        if args["doExtension"] and truncatedPlaintextFilePath.endswith(FILEEXT):
            truncatedPlaintextFilePath = truncatedPlaintextFilePath[:-len(FILEEXT)]
    else:
        truncatedPlaintextFilePath = metadata['path']
    plaintextFilePath = os.path.join(args["output"], truncatedPlaintextFilePath)
    
    # Ignore file if it does not pass through the include/exclude pattern filters
    if doInclude(truncatedPlaintextFilePath, args["patterns"]) == False:
        return

    # Show the major operation being performed
    if args["isVerbose"]:
        print("Decrypting file: " + ciphertextFilePath + " -> " + plaintextFilePath)

    # Check if file already exists
    if os.path.exists(plaintextFilePath):
        # Check if the file should be overwritten
        if args["doForce"]:
            # Overwrite the file
            if args["isVerbose"]:
                print("Warning: Overwriting file: " + plaintextFilePath)
        else:
            # Skip the file
            if args["isVerbose"]:
                print("Warning: Skipping file: " + plaintextFilePath)
            return

    # Skip the actual decryption if this is a dry run
    if args["doDryRun"]:
        return
    
    # Raise the offset for the data
    offset += 64 + encryptedMetadataLen

    # Attempt to decrypt the encrypted data
    encryptedData = ciphertext[(offset + 32):]
    data          = None
    try:
        data = symmetricCryptography.decrypt(encryptedData)
    except:
        print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".", file = sys.stderr)
        with stats["mutex"]:
            stats["failed"] += 1
        return
    
    # Verify the encrypted data signature
    encryptedDataSig = ciphertext[offset:(offset + 32)]
    if secrets["pepper"]:
        if hmac.new(secrets["pepper"], encryptedData, hashlib.sha256).digest() != encryptedDataSig:
            print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".", file = sys.stderr)
            with stats["mutex"]:
                stats["failed"] += 1
            return
    else:
        if hashlib.sha256(encryptedData).digest() != encryptedDataSig:
            print("Error: Failed to decrypt \"" + ciphertextFilePath + "\".", file = sys.stderr)
            with stats["mutex"]:
                stats["failed"] += 1
            return
    
    # Create the required directory structure in the output
    plaintextFileDir = os.path.dirname(plaintextFilePath)
    if not os.path.exists(plaintextFileDir):
        os.makedirs(plaintextFileDir)
    
    # Write the file to disk
    success = safeWrite(plaintextFilePath, data, args["doShred"])
    if success == False:
        return
    
    # Rename the temporary file to the actual file
    os.rename(plaintextFilePath + ".tmp", plaintextFilePath)

    # Set the file's other metadata
    os.utime(plaintextFilePath, (metadata['mtime'], metadata['mtime']))

    # If cleanup is enabled, delete the ciphertext file
    if args["doCleanup"]:
        deleteFile(ciphertextFilePath, args["doShred"], args["isVerbose"])
    
    # Increment the number of successful files
    with stats["mutex"]:
        stats["successful"] += 1

def decrypt(args, secrets, stats):
    # Import the private key
    asymmetricCryptography = AsymmetricKey()
    asymmetricCryptography.importKey(args["key"], False, args["passFile"])
    secrets["key"] = asymmetricCryptography

    # Gather a list of (possibly nested) files to encrypt
    ciphertextFilePaths = ls(args["input"])

    # Iterate through the files
    threads = [ ]
    for truncatedCiphertextFilePath in ciphertextFilePaths:
        stats["total"] += 1
        thread = Thread(target = decryptFile, args = (truncatedCiphertextFilePath, args, secrets, stats))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    
    # Print the number of failed files
    if stats["failed"] > 0:
        print("Error: Failed to decrypt " + str(stats["failed"]) + " file(s)!", file = sys.stderr)
        sys.exit(2)

    # Delete everything in the input, directories included, if set to do so
    if args["doClearInput"]:
        clearInput(args["input"], args["isVerbose"])
