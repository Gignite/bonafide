# 0.2.0 (01/21/2011)

- Added support for bcrypt (Wouterr)
- Added support for PBKDF2 (isaiahdw)
- Removed Bonafide_Mechanism::$prefix
- Changed configuration syntax

Configuration for mechanisms is now:

    string $prefix => array(string $mechanism, array $config)

# 0.1.0 (01/11/2011)

Initial release, support for HMAC and legacy Auth hashing
