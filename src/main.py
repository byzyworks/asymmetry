#!/usr/bin/env python3

import getopt
import os
import re
import sys
from   threading import Lock

from algorithm import encrypt, decrypt

# Version information
VERSION = "1.2.1"

# Get script directory
PYTHON  = '/usr/bin/python3'
THIS    = os.path.realpath(os.path.abspath(__file__))
THISDIR = os.path.dirname(THIS)

# Show help information
def usage():
    print("Usage: " + PYTHON + " " + THIS + " --encrypt [OPTIONS]")
    print("       " + PYTHON + " " + THIS + " --decrypt [OPTIONS]")
    print("Options:")
    print("  -c, --cleanup           Enables automatic shredding of files in input directory upon successful output")
    print("  -d, --decrypt           Flag program to decrypt input directory into output directory (reverse of encryption, cannot be used with it also enabled)")
    print("  -e, --encrypt           Flag program to encrypt input directory into output directory (reverse of decryption, cannot be used with it also enabled)")
    print("  -f, --force             Overwrite files in output directory if they already exist")
    print("  -h, --help              Display help message")
    print("  -i, --input=<dir>       Input directory (if encrypting should contain plaintext files, and if decrypting should contain encrypted (via. this program) files)")
    print("  -k, --key=<file>        Asymmetric key file to use for encryption/decryption (if encrypting should be public key, and if decrypting should be private key)")
    print("  -l, --ls                List the paths of the files in the output directory (paired with their input files), without actually creating them")
    print("  -n, --include=<regex>   Regular expression for directory inside the input directory (must be encrypted) to include the scope of the operation to; for decryption, based on the original directory structure recorded in the encrypted metadata. Can be given multiple times, and will be processed in order.")
    print("  -o, --output=<dir>      Output directory (if encrypting should contain encrypted files, and if decrypting should contain plaintext files)")
    print("  -P, --passfile=<file>   File (or descriptor) with contents to use for decrypting the imported private key for file decryption, if needed")
    print("  -p, --pepper=<file>     (Re-usable) secret input used when generating hashed names for the encrypted files (when the metadata is encrypted); optional, but strongly recommended for security reasons")
    print("  -R, --retain-paths      Retain the metadata and directory structure of the input files when encrypting (default is to store the files flat with the metadata encrypted) or decrypting (default is to restore the encrypted metadata)")
    print("  -v, --verbose           Display verbose output")
    print("  -V, --version           Display version information")
    print("  -x, --exclude=<regex>   Regular expression for directory inside the input directory (must be encrypted) to exclude the scope of the operation from; for decryption, based on the original directory structure recorded in the encrypted metadata. Can be given multiple times, and will be processed in order.")
    print("  --clear-input           Delete the contents of the input directory after a successful encryption/decryption. Also enables --cleanup, but this will ensure the emptied sub-directories are also deleted. This argument cannot be used in combination with --include or --exclude, and will fail if there are still files in the input directory after cleanup.")
    print("  --no-file-extension     Do not append the \".asym\" file extension to encrypted files (or try to get rid of it when decrypting)")
    print("  --no-shred              Do not shred/zero-fill files in the input directory when cleanup is enabled; they will simply be deleted")

# Show version information
def version():
    print("Asymmetry File System v" + VERSION)

def main(argv):
    # Define program arguments
    try:
        opts, parsedArgs = getopt.getopt(argv, "cdefhi:k:ln:o:P:p:RvVx:", [
            "cleanup",
            "decrypt",
            "encrypt",
            "exclude=",
            "force",
            "help",
            "include=",
            "input=",
            "key=",
            "ls",
            "output=",
            "passfile=",
            "pepper=",
            "retain-paths",
            "verbose",
            "version",
            "clear-input",
            "no-file-extension",
            "no-shred"
        ])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    # Variables (with default values) for options
    parsedArgs = {
        "doCleanup":    False,
        "doClearInput": False,
        "doDryRun":     False,
        "doEncrypt":    None,
        "doExtension":  True,
        "doForce":      False,
        "doSamePaths":  False,
        "doShred":      True,
        "input":        None,
        "isVerbose":    False,
        "key":          None,
        "output":       None,
        "passFile":     None,
        "patterns":     [ ],
        "pepper":       None
    }
    secrets = {
        "key":    None,
        "pepper": None
    }
    
    # Parse program arguments
    for opt, arg in opts:
        if opt in ("-c", "--cleanup"):
            parsedArgs["doCleanup"] = True
        elif opt in ("--clear-input"):
            parsedArgs["doCleanup"]    = True
            parsedArgs["doClearInput"] = True
        elif opt in ("-d", "--decrypt"):
            if parsedArgs["doEncrypt"] == True:
                print("Error: Cannot enable both encryption and decryption modes at the same time.")
                sys.exit(2)
            parsedArgs["doEncrypt"] = False
        elif opt in ("-e", "--encrypt"):
            if parsedArgs["doEncrypt"] == False:
                print("Error: Cannot enable both encryption and decryption modes at the same time.")
                sys.exit(2)
            parsedArgs["doEncrypt"] = True
        elif opt in ("-f", "--force"):
            parsedArgs["doForce"] = True
        elif opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-n", "--include"):
            pattern = None
            try:
                pattern = re.compile(arg)
            except re.error:
                print("Error: The include pattern is required to be a valid regular expression.")
                sys.exit(2)
            parsedArgs["patterns"].append(True)
            parsedArgs["patterns"].append(pattern)
        elif opt in ("-i", "--input"):
            parsedArgs["input"] = arg
            if not os.path.isdir(parsedArgs["input"]):
                print("Error: The input source is required to be an accessible directory.")
                sys.exit(2)
        elif opt in ("-k", "--key"):
            parsedArgs["key"] = arg
            if not os.path.isfile(parsedArgs["key"]):
                print("Error: The key is required to be an accessible file.")
                sys.exit(2)
        elif opt in ("-l", "--ls"):
            parsedArgs["doDryRun"] = True
        elif opt in ("--no-file-extension"):
            parsedArgs["doExtension"] = False
        elif opt in ("--no-shred"):
            if parsedArgs["doCleanup"] == False:
                print("Warning: --no-shred has no effect when cleanup is disabled.")
            parsedArgs["doShred"] = False
        elif opt in ("-o", "--output"):
            parsedArgs["output"] = arg
            if not os.path.isdir(parsedArgs["output"]):
                print("Error: The output destination is required to be an accessible directory.")
                sys.exit(2)
        elif opt in ("-P", "--passfile"):
            parsedArgs["passFile"] = arg
            if not os.path.isfile(parsedArgs["passFile"]):
                print("Error: The passfile is required to be an accessible file.")
                sys.exit(2)
            if parsedArgs["doEncrypt"] == True:
                print("Warning: There is no need for --passfile when encrypting.")
        elif opt in ("-p", "--pepper"):
            parsedArgs["pepper"] = arg
            if not os.path.isfile(parsedArgs["pepper"]):
                print("Error: The pepper is required to be an accessible file.")
                sys.exit(2)
            with open(arg, 'rb') as f:
                secrets["pepper"] = f.read()
        elif opt in ("-R", "--retain-paths"):
            if parsedArgs["doEncrypt"] == False:
                print("Warning: --retain-paths has no effect when decrypting.")
            parsedArgs["doSamePaths"] = True
        elif opt in ("-v", "--verbose"):
            parsedArgs["isVerbose"] = True
        elif opt in ("-V", "--version"):
            version()
            sys.exit()
        elif opt in ("-x", "--exclude"):
            pattern = None
            try:
                pattern = re.compile(arg)
            except re.error:
                print("Error: The exclude pattern is required to be a valid regular expression.")
                sys.exit(2)
            parsedArgs["patterns"].append(False)
            parsedArgs["patterns"].append(pattern)

    if parsedArgs["doEncrypt"] == None:
        print("Error: Must specify either encryption or decryption mode.")
        sys.exit(2)
    
    if parsedArgs["key"] == None:
        print("Error: A key is required for encryption or decryption.")
        sys.exit(2)

    if parsedArgs["input"] == None:
        print("Error: An input directory is required to encrypt or decrypt.")
        sys.exit(2)
    
    if parsedArgs["output"] == None:
        print("Error: An output directory is required to encrypt or decrypt.")
        sys.exit(2)

    if parsedArgs["doClearInput"] and (len(parsedArgs["patterns"]) > 0):
        print("Error: Cannot use --clear-input with pattern filtering via. --include or --exclude.")
        sys.exit(2)

    # Track the number of successful and failed files
    stats = {
        "total":      0,
        "successful": 0,
        "failed":     0,
        "mutex":      Lock()
    }

    # Start encryption/decryption process
    if parsedArgs["doEncrypt"]:
        if parsedArgs["isVerbose"]:
            print("Attempting to encrypt files in \"" + parsedArgs["input"] + "\" into \"" + parsedArgs["output"] + "\" using key \"" + parsedArgs["key"] + "\"...")
        encrypt(parsedArgs, secrets, stats)
    else:
        if parsedArgs["isVerbose"]:
            print("Attempting to decrypt files in \"" + parsedArgs["input"] + "\" into \"" + parsedArgs["output"] + "\" using key \"" + parsedArgs["key"] + "\"...")
        decrypt(parsedArgs, secrets, stats)

if __name__ == "__main__":
   main(sys.argv[1:])