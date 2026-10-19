# win32_hash

Password hashing and verification for Windows, written in Ada/SPARK.

It derives a hash with PBKDF2-HMAC-SHA256 through the Windows CNG API (bcrypt),
generates a random salt, stores it as Base64, and wipes every secret it touches.
Almost all of the code is proved with GNATprove; the few parts that talk directly to Windows are not,
and the README says exactly which ones.

Status: this library has not had an external security audit. See Limitations.

## Features
- PBKDF2-HMAC-SHA256 key derivation through BCryptDeriveKeyPBKDF2.
- Random salt of 32 to 256 bytes. Main entropy source is ProcessPrng, with BCryptGenRandom as fallback.
- Salt stored as Base64 (RFC 4648, with padding); hash stored as 64 uppercase hexadecimal characters.
- Separate verification procedure, with a constant-time comparison and a fail-closed result.
- The password is overwritten as soon as it has been used, on success and on every failure path.
- Strongly typed ranges (subtypes) for every length, index and buffer.
- Contracts (Pre, Post, Global, Depends) on the public procedures, checked at run time and proved by GNATprove where the body is in SPARK.

## Requirements
- Windows only. The code imports bcrypt (BCryptOpenAlgorithmProvider,
  BCryptDeriveKeyPBKDF2, BCryptCloseAlgorithmProvider, BCryptGenRandom) and ProcessPrng, and uses SecureZeroMemory.
- An Ada 2012 compiler with SPARK support (GNAT).
- Alire (the project has an alire.toml).
- GNATprove 16.x, only if you want to re-run the proofs. alire.toml declares gnatprove = "^16.1.0" (16.1.0 or newer within 16.x).

## Build and run
- alr build
- alr run

alr run executes the win32_hash executable declared in alire.toml,
the demo in win32_hash.adb, which hashes a password and then verifies it twice:
once with a different password (it must fail) and once with the same password (it must succeed).

## API
- PBKDF2_Hash_Data.Data (registration)
- Field	Meaning	Range / default
- Password	Password, in a 512-character buffer	characters '!' .. '~'; default all '0'
- Password_Length	Characters actually used	12 .. 512; default 12
- Salt	Output: Base64 salt	344-character buffer; default all '0'
- Salt_Length	Output: valid characters in Salt	44 .. 344
- Salt_Maximum	Input: how many random salt bytes to generate	32 .. 256; default 32
- Hash	Output: 64 uppercase hex characters	default all '0'
- Status	0 on success, anything else is a failure	default NTSTATUS'Last

## Public_Hash (Item : in out Data)

Generates a random salt and derives the hash.

- Precondition: the password is not all '0'; Salt and Hash are all '0';
  Status /= 0. A fresh Data record already satisfies this. If you reuse a record, reset it first.
- Postcondition: the password is overwritten with '0'. If Status = 0,
  Salt (1 .. Salt_Length) holds the Base64 salt and the rest of Salt is '0'. If Status /= 0, Salt is all '0'.
- On any failure the procedure also overwrites Password, Salt and Hash, and sets Status to NTSTATUS'Last.
- Global => (In_Out => Wrapper_ZeroMemory.Secure_Clean).

## Public_Verify (Item : in out Verify_Data)

Decodes the stored salt, derives the hash again with Item.Iteration, and compares it with Item.Hash.

- Treat the result as a match only if Status = 0, Diff = 0 and Matches.
- Whether the check succeeds or fails, Password, Hash and Salt come back as all '0'.
- Any internal failure (invalid salt, bcrypt error) ends as "no match" with Status /= 0.
  A wrong password and an internal error are therefore not distinguished by Matches; use Status for that.

## Security design
- Algorithm: PBKDF2 with HMAC-SHA256, derived key of 32 bytes.
- Iterations are limited to 650 000 .. 1 000 000 by the type; the default is 1 000 000.
- Salt: random per hash, 32 to 256 bytes, from ProcessPrng, falling back to BCryptGenRandom. An all-zero salt is rejected.
- Wiping: every buffer that held a secret is cleared with SecureZeroMemory, and then overwritten again in Ada. The second clear is deliberate redundancy; it is kept       even though it looks repeated.
- Cleanup does not depend on assertions. The wiping on failure paths is ordinary code, not a contract, so it runs whether assertions are enabled or not.
- Constant-time comparison: Public_Verify scans all 64 characters and accumulates differences, instead of stopping at the first mismatch.
- Fail closed: the result starts as "no match" and only becomes "match" after the whole check has succeeded.
- Provider handle: the CNG handle is closed once and then set to null, so the error handler cannot close it a second time.

## Formal verification

The SPARK part of the project is proved with GNATprove. Bodies marked SPARK_Mode => Off are not analysed (see below).

Result
- Project proved with --level=4, all provers, 0 unproved checks:
- GNATprove	Result
- SPARK 16.1.0 (Alire)	186 checks, all proved, 0 unproved
- SPARK Community 2021 (20210519)	all proved, 0 unproved

## To re-run:
alr gnatprove --level=4 --prover=all --report=all -j10 --steps=10_000_000 --timeout=1_000_000

## What is proved
- No run-time errors in all the SPARK code: no index, range, overflow, division or initialization failures.
- Encode.Salt_Encode: the output length is 4 * ceil(N / 3), the padding = appears only in the last positions, and every other character belongs to the Base64 alphabet.
- Decode.Salt_Decode: when Valid, every byte written to Item is exactly the byte that the Base64 text represents, and the length is the exact number of decoded bytes.     When not Valid, the whole buffer is zero.
- Convert (bytes to hexadecimal): the result is hexadecimal and, if any input byte is non-zero, the result is not all zeros.
- Public_Hash and Public_Verify: their postconditions are proved from the contracts of Hash and Verify, which are declared in the specification with the same contract.
- Global and Depends on the public procedures.

## What is not proved
- Hash and Verify bodies (SPARK_Mode => Off, because they take the 'Address of buffers to call the Windows API). Their contracts are checked at run time only. GNATprove   trusts them when proving the code around them.
- Bodies of Wrapper_ProcessPrng, Wrapper_BcryptGenRandom and Wrapper_ZeroMemory, and the demo program.

## Run-time behaviour

The package sets pragma Assertion_Policy (Check), so contracts are checked at run time.

If a caller breaks a precondition, the check fails before the body does anything.
The defensive checks inside the code (for example the validation after Salt_Encode's loop) do not depend on contracts; when they find a problem, the output buffer is returned as all '0'.

## Limitations
- Not audited. No external security review. Do not describe this as "secure" without that qualification.
- Windows only.
- Wiping is best effort. It clears the buffers the library controls. It cannot reach copies made by the operating system, the runtime or the hardware
  (swap files, registers, crash dumps).
- Password format: 12 to 512 characters, from '!' to '~'. Spaces and non-ASCII characters are not accepted.
- Iterations are not stored in Data. Public_Hash always uses Get_Iterations. Store that value next to the hash,
  so you can still verify old hashes if the default  changes.
- No pepper and no password-strength policy. Beyond length and character range, the library does not check how guessable a password is.
- Iteration advice changes over time. The default of 1 000 000 is a design choice, not a guarantee. Review it against current recommendations.
