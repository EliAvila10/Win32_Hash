win32_hash

Password hashing and verification for Windows, written in Ada/SPARK.

It derives a hash with PBKDF2-HMAC-SHA256 through the Windows CNG API (bcrypt),
generates a random salt, stores it as Base64, and wipes every secret it touches.
Almost all of the code is proved with GNATprove; the few parts that talk directly to Windows are not,
and the README says exactly which ones.

Status: this library has not had an external security audit. See Limitations.
