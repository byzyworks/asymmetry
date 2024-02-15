# Asymmetry File System

Asymmetry File System ("AsyFiS") is a Python-based command line utility for bulk file encryption (not to be confused with "filesystems" such as NTFS or ext4 - this is not that, technically-speaking).

## Reasoning

This was created as a way to create and support systems of files which can be "write-only", in the sense that the mechanisms for reading vs. writing of affected directories can exist and be supported using separate keys. As a result of this desire are a couple of design decisions that influenced the making of this:

The first should be pretty obvious. AsyFiS uses asymmetric encryption for affected files. More accurately, the files themselves are encrypted via. symmetric encryption for performance reasons, while each per-file auto-generated symmetric key is encrypted via. a pre-generated asymmetric public(?) key from the user. If the private key for decryption is withheld, a "write-only" filesystem can, to some extent, be simulated, whereby the user could still append their system with new encrypted files (encrypted via. their public key) and make other filesystem-level changes accordingly - they just would not be able to view the underlying plaintext of those files without their public key's corresponding private key.

Similar to this, and unlike a similar program with different aims such as Veracrypt, encryption/decryption is done at the file-level as opposed to the block-level. That is because filesystems, which would be affected/encrypted at the block-level, cannot easily be written to (as is needed when creating, overwriting, or deleting files within them) without also being read and parsed, at risk of causing corruption. Hence, the aims of block-level encryption are better and more practically achieved with a symmetric solution such as Veracrypt, and this (AsyFiS) shouldn't be used to replace that, but rather complement it whenever possible. Veracrypt and AsyFiS support different access patterns, and it's preferred that this is used in cases where encryption/decryption would be infrequent.

## What This Does

This script takes an input directory, traverses the files inside it recursively, encrypting each file one-by-one, and then outputs each of the encrypted files into an output directory. By default, file "metadata" is also encrypted, including the file's relative path within the input directory, such that once the file is encrypted, it is stored flat inside the output directory (regardly of how nested within the input directory it was previously) with a name that is hashed from said file path, which can be HMAC'd with a shared pepper file for additional security against known-plaintext cryptanalysis. This scheme reveals minimal information with the intended exception of maintaining that two files should never have conflicting plaintext file paths, such that no two ciphertext files ever map to the same plaintext file. If the pepper between two files at risk of overlap is ever changed, this is not guaranteed, just as if, for whatever reason, these files are renamed by the user in other ways.

```
out/f21c0f03b1496aa41a54579705ac5c1376d446dec7cde4c533fb26712fc9df32.asym <- in/3
out/6c4789c44ded3b8f4695fb833951904f7b912a43ce59c12331f15dd41d1d8892.asym <- in/a/1
out/2c26e7def7f5d1764ac89e13e6745c5335242b852e789e3d39cfeb972e48be3a.asym <- in/b/2.txt
```

The encryption process is made up of these several parts:

1. A constant 8-byte filetype signature is appended at the start of the encrypted file to notify the file was encrypted using this process.

2. A symmetric 256-bit AES key is generated for the file, which is then encrypted with the user-provided asymmetric public key, and then SHA-256 hashed (HMAC'd as well if a pepper is provided). Each of these acquired pieces are then stored with the encrypted file in three respective parts: the hash/MAC (32 bytes), the length of the encrypted key in bytes (32 bytes), and the encrypted symmetric key (variable bytes).

3. Metadata, including the file's relative path (within the input directory) and it's last-modified date, is compiled into a JSON-formatted structure and encrypted with the symmetric key, and then SHA-256 hashed (HMAC'd as well if a pepper is provided). Each of these acquired pieces are then stored with the encrypted file in three respective parts: the hash/MAC (32 bytes), the length of the encrypted metadata in bytes (32 bytes), and the encrypted metadata (variable bytes).

4. The file data itself is encrypted with the symmetric key, and then SHA-256 hashed (HMAC'd as well if a pepper is provided). Each of these acquired pieces are then stored with the encrypted file in two respective parts: the hash/MAC (32 bytes), and the encrypted file data (variable bytes), which extends until the end of the encrypted file.

5. The file is then written to disk in the output directory (flattened) with a name derived from a SHA-256 hash of the file name (HMAC'd as well if a pepper is provided) followed by the ".asym" file extension. The details of this may change depending on enabled program arguments.

Similarly, with decryption:

1. The script attempts to verify the file was created via. this same script's encryption process by verifying the filetype signature (it will skip over non-applicable files this way, or if they're too small to have even the 8-byte signature).

2. The encrypted symmetric key is hashed and verified against the stored hash/MAC (using the pepper if necessary). If verification fails, the file is skipped. If not, the symmetric key is decrypted with the user-provided asymmetric private key, and the process continues.

3. The encrypted metadata is hashed and verified against the stored hash/MAC (using the pepper if necessary). If verification fails, the file is skipped. If not, the metadata is decrypted (and parsed) with the already-decrypted symmetric key, and the process continues. Various checks are made regarding the plaintext file path at this point (such as to avoid conflict in the output directory).

4. The encrypted metadata is hashed and verified against the stored hash/MAC (using the pepper if necessary). If verification fails, the file is skipped. If not, the file is decrypted with the already-decrypted symmetric key, and the file is stored accordingly with the already-decrypted metadata applied over it, including its original relative path.

5. The file is then written to disk in the output directory using the original relative path of the file previously stored in the encrypted metadata, creating the necessary sub-level directories as needed. The details of this may change depending on enabled program arguments.

## Additional Features

* The original pathing of the files encrypted using this process can optionally be maintained via. an argument to the script "`--retain-paths`". The ".asym" file extension will still be added to the files upon encryption (and subsequently removed upon decryption) unless the "`--no-file-extension`" option is set. It is possible, but not recommended to use "`--retain-paths`" and "`--no-file-extension`" simultaneously.

* Plaintext file paths can be filtered within the input (whether encrypting or decrypting) according to orderly parsing of glob patterns that the user provides through "`--include`" and "`--exclude`", respectively, where the glob patterns identify relative file paths (or part of) in the input directory, always using their plaintext paths for comparison (in the case of encrypted files, this is what is stored in the encrypted metadata, not the actual file path seen by the user). Both options can be provided multiple times, and will be parsed in the order that they appear in a non-greedy way. Note as well that if the first of any is an "`--include`" statement, then the default behavior will be to exclude everything else, and if the first of any is an "`--exclude`" statement, then the default behavior will be to include everything. Files that lie outside of this path (per their plaintext forms) are thus ignored from encryption/decryption.

* Automatic deletion of input files is optional with `--cleanup`, which is set as well to zero-fill the files by default before deletion unless `--no-shred` is also set. Automatic deletion of input directories is optional with `--clear-input`, which auto-enables `--cleanup` with set.

* Dry runs are possible via. "`--ls`", which will stop the script short of actually encrypting/decrypting anything. This should be paired with "`--verbose`".

## Notable Issues

This was tested using an 2048-bit RSA keypair generated via. OpenSSL to an X.509 certificate (.pem/.pub). It does not currently work with Ed25519 keypairs (my personal favorite), and is not verified to work with ECDSA keypairs, or with keypairs which are not X.509-formatted, such as those generated via. OpenSSH or PuTTy.

In general, the choice of algorithms is relatively inflexible, and based on personal preference with respect to upholding strong security. The option of what algorithms to use could be provided in the future to make the script more useful.