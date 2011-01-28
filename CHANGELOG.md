# 0.4.0 (01/27/2011)

- Modified bcrypt mechanism to allow setting per-user salt and iteration (issue #4)
- Modified bcrypt to generate salts using the full range of possible characters
- Improved unit test coverage
- Added Bonafide_ACL class for creating access control lists

# 0.3.0 (01/23/2011)

- Fixed a bug that would prevent using "/" as a prefix
- Added new method Bonafide::latest for checking if a hash is up to date
- Abstracted prefix capturing to Bonafide::prefix

# 0.2.0 (01/21/2011)

- Added support for bcrypt (Wouterr)
- Added support for PBKDF2 (isaiahdw)
- Removed Bonafide_Mechanism::$prefix
- Changed configuration syntax

Configuration for mechanisms is now:

    string $prefix => array(string $mechanism, array $config)

# 0.1.0 (01/11/2011)

Initial release, support for HMAC and legacy Auth hashing
