# Change Log

## 1.3.0

- Added per-file multi-threading
- Fixed error messages being printed to stdout instead of stderr
- Some refactoring

## 1.2.1

- Fixed ciphertext being written back to output on decryption
- Fixed redundant notification about shredding/deletion of affected files in addition to overwrite notification (with `--force`)

## 1.2.0

- Removed `--narrow=<path>` command line option, which has now been replaced with `--include=<regex>`
- Added `--include=<regex>` and `--exclude=<regex>` commands that use regular expressions, and can be re-stated multiple times each to filter files/directories based on their plaintext paths, where they will be parsed in left-to-right order
- Added `--clear-input` command line option to remove empty directories from input, which automatically enables `--cleanup` as well
- Added `--no-shred` command line option to disable zero-filling when using `--cleanup`
- Changed automatic appending of ".asym" file extension upon encryption to be default behavior even when `--retain-paths` is not enabled
- Added code for removing/reversing ".asym" extension upon decryption
- Added `--no-file-extension` to disable ".asym" appendage/removal for encryption or decryption, respectively
- Removed saving and restoration of GID, UID, and permissions bits in encrypted metadata (due to potentially undesirable/unexpected behavior / better compatibility with non-Linux systems)
- Some refactoring and improved exception-handling

## 1.1.0

- Added support for passphrase-encrypted private keys
- Fixed failed decryptions due to bad offsetting based on old 6-byte filetype signature

## 1.0.0

- Initial release

## Format

The version number is made of 3 parts:

"`(major version number) . (feature update number) . (hotfix number)`"

The encrypted file format produced by one major version is not guaranteed compatibility to be read and decrypted by other major versions of this same program. Changes to default ciphers, or additional supported (or removed) ciphers also constitute major version upgrades due to potential introduction of incompatibilities with older versions of the program.