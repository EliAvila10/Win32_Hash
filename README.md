# win32_hash

Password hashing and verification for Windows, written in Ada/SPARK.

It derives a hash with PBKDF2-HMAC-SHA256 through the Windows CNG API (bcrypt),
generates a random salt, stores it as Base64, and wipes every secret it touches.
Almost all of the code is proved with GNATprove; the few parts that talk directly to Windows are not,
and the README says exactly which ones.

Status: this library has not had an external security audit. See Limitations.

## Contents
- **Features
> Requirements
> Build and run
> Quick start
> API
> Security design
> Formal verification
> Run-time behaviour
> Limitations
> Project layout
> License

## Features
> PBKDF2-HMAC-SHA256 key derivation through BCryptDeriveKeyPBKDF2.
> Random salt of 32 to 256 bytes. Main entropy source is ProcessPrng, with BCryptGenRandom as fallback.
> Salt stored as Base64 (RFC 4648, with padding); hash stored as 64 uppercase hexadecimal characters.
> Separate verification procedure, with a constant-time comparison and a fail-closed result.
> The password is overwritten as soon as it has been used, on success and on every failure path.
> Strongly typed ranges (subtypes) for every length, index and buffer.
> Contracts (Pre, Post, Global, Depends) on the public procedures, checked at run time and proved by GNATprove where the body is in SPARK.

## Requirements
> Windows only. The code imports bcrypt (BCryptOpenAlgorithmProvider,
  BCryptDeriveKeyPBKDF2, BCryptCloseAlgorithmProvider, BCryptGenRandom) and ProcessPrng, and uses SecureZeroMemory.
> An Ada 2012 compiler with SPARK support (GNAT).
> Alire (the project has an alire.toml).
> GNATprove 16.x, only if you want to re-run the proofs. alire.toml declares gnatprove = "^16.1.0" (16.1.0 or newer within 16.x).

## Build and run
alr build
alr run

alr run executes the win32_hash executable declared in alire.toml,
the demo in win32_hash.adb, which hashes a password and then verifies it twice:
once with a different password (it must fail) and once with the same password (it must succeed).

## API
> PBKDF2_Hash_Data.Data (registration)
> Field	Meaning	Range / default
> Password	Password, in a 512-character buffer	characters '!' .. '~'; default all '0'
> Password_Length	Characters actually used	12 .. 512; default 12
> Salt	Output: Base64 salt	344-character buffer; default all '0'
> Salt_Length	Output: valid characters in Salt	44 .. 344
> Salt_Maximum	Input: how many random salt bytes to generate	32 .. 256; default 32
> Hash	Output: 64 uppercase hex characters	default all '0'
> Status	0 on success, anything else is a failure	default NTSTATUS'Last
