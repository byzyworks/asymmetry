#!/usr/bin/env python3

import fs
import getopt
import os
import sys

from algorithm import encrypt, decrypt

# Version information
VERSION = "1.0.0"

# Get script directory
PYTHON  = '/usr/bin/python3'
THIS    = os.path.realpath(os.path.abspath(__file__))
THISDIR = os.path.dirname(THIS)

# Show help information
def usage():
    print("Usage: " + PYTHON + " " + THIS + " --encrypt [OPTIONS]")
    print("       " + PYTHON + " " + THIS + " --decrypt [OPTIONS]")
    print("Options:")
    print("  -c, --cleanup       Enables automatic shredding of files in input directory upon successful output")
    print("  -d, --decrypt       Flag program to decrypt input directory into output directory (reverse of encryption, cannot be used with it also enabled)")
    print("  -e, --encrypt       Flag program to encrypt input directory into output directory (reverse of decryption, cannot be used with it also enabled)")
    print("  -f, --force         Overwrite files in output directory if they already exist")
    print("  -h, --help          Display help message")
    print("  -i, --input=<dir>   Input directory (if encrypting should contain plaintext files, and if decrypting should contain encrypted (via. this program) files)")
    print("  -k, --key=<file>    Asymmetric key file to use for encryption/decryption (if encrypting should be public key, and if decrypting should be private key)")
    print("  -l, --ls            List the paths of the files in the output directory (paired with their input files), without actually creating them")
    print("  -n, --narrow=<dir>  Directory inside the input directory (must be encrypted) to narrow the scope of the operation to; for decryption, based on the original directory structure recorded in the encrypted metadata")
    print("  -o, --output=<dir>  Output directory (if encrypting should contain encrypted files, and if decrypting should contain plaintext files)")
    print("  -p, --pepper=<file> (Re-usable) secret input used when generating hashed names for the encrypted files (when the metadata is encrypted); optional, but strongly recommended for security reasons")
    print("  -R, --retain-paths  Retain the metadata and directory structure of the input directory when encrypting (default is to store the files flat with the metadata encrypted)")
    print("  -v, --verbose       Display verbose output")
    print("  -V, --version       Display version information")

# Show version information
def version():
    print("Asymmetry File System v" + VERSION)

def main(argv):
    # Define program arguments
    try:
        opts, args = getopt.getopt(argv, "cdefhiklnopRvV", [
            "cleanup",
            "decrypt",
            "encrypt",
            "force",
            "help",
            "input=",
            "key=",
            "ls",
            "narrow=",
            "output=",
            "pepper=",
            "retain-paths",
            "verbose",
            "version"
        ])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    # Variables (with default values) for options
    cleanup   = False
    doEncrypt = None
    dryRun    = False
    force     = False
    key       = None
    input     = None
    narrow    = None
    output    = None
    pepper    = None
    samePaths = False
    verbose   = False
    
    # Parse program arguments
    for opt, arg in opts:
        if opt in ("-c", "--cleanup"):
            cleanup = True
        elif opt in ("-d", "--decrypt"):
            if doEncrypt == True:
                print("Error: Cannot enable both encryption and decryption modes at the same time.")
                sys.exit(2)
            doEncrypt = False
        elif opt in ("-e", "--encrypt"):
            if doEncrypt == False:
                print("Error: Cannot enable both encryption and decryption modes at the same time.")
                sys.exit(2)
            doEncrypt = True
        elif opt in ("-f", "--force"):
            force = True
        elif opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-i", "--input"):
            input = arg
            if not os.path.isdir(input):
                print("Error: The input source is required to be an accessible directory.")
                sys.exit(2)
        elif opt in ("-k", "--key"):
            key = arg
            if not os.path.isfile(key):
                print("Error: The key is required to be an accessible file.")
                sys.exit(2)
        elif opt in ("-l", "--ls"):
            dryRun = True
        elif opt in ("-n", "--narrow"):
            narrow = arg
        elif opt in ("-o", "--output"):
            output = arg
            if not os.path.isdir(output):
                print("Error: The output destination is required to be an accessible directory.")
                sys.exit(2)
        elif opt in ("-p", "--pepper"):
            pepper = arg
            if not os.path.isfile(pepper):
                print("Error: The pepper is required to be an accessible file.")
                sys.exit(2)
        elif opt in ("-R", "--retain-paths"):
            if doEncrypt == False:
                print("Warning: --retain-paths has no effect when decrypting.")
            samePaths = True
        elif opt in ("-v", "--verbose"):
            verbose = True
        elif opt in ("-V", "--version"):
            version()
            sys.exit()

    if doEncrypt == None:
        print("Error: Must specify either encryption or decryption mode.")
        sys.exit(2)
    
    if key == None:
        print("Error: A key is required for encryption or decryption.")
        sys.exit(2)

    if input == None:
        print("Error: An input directory is required to encrypt or decrypt.")
        sys.exit(2)
    
    if output == None:
        print("Error: An output directory is required to encrypt or decrypt.")
        sys.exit(2)

    # Start encryption/decryption process
    if doEncrypt:
        if verbose:
            print("Attempting to encrypt files in " + input + " into " + output + " using key " + key + "...")
        encrypt(input, output, key, pepper, narrow, force, cleanup, dryRun, samePaths, verbose)
    else:
        if verbose:
            print("Attempting to decrypt files in " + input + " into " + output + " using key " + key + "...")
        decrypt(input, output, key, pepper, narrow, force, cleanup, dryRun, verbose)

if __name__ == "__main__":
   main(sys.argv[1:])