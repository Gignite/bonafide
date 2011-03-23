# 0.5.3.1 (03/23/2011)

- Fixed calls to `array_combine()` that were not checking for an empty array

# 0.5.3 (03/18/2011)

- Added new constants `ROLE`, `ACTION`, and `RESOURCE` to `Bonafide_ACL`
- Added new method `Bonafide_ACL::has($entity, $name)` for checking if a role, action, or resource already exists

# 0.5.2 (03/18/2011)

- Renamed `Bonafide_Core` to `Kohana_Bonafide` and `Bonafide_ACL_Core` to `Kohana_Bonafide_ACL`, following standard module class name conventions
- Added `$resources` parameter to `Bonafide_ACL::matrix` and `Bonafide_ACL::actions`, allows getting a matrix for a specific set of resources

# 0.5.1 (03/13/2011)

- Added `__wakeup` method to Bonafide and Bonafide_ACL, restores instances when unserialized
- Remove references to `static::` in Bonafide_ACL for PHP 5.2 compatibility

# 0.5.0 (03/13/2011)

- Complete refactor of ACL class
    - Roles are now copied, rather than inherited
    - Permissions are now checked from less to more specific, and all permissions are checked before return
    - Actions are now grouped by resource and must be defined when creating the resource
    - Added new `matrix()` method, returns the entire resource/action matrix
    - Added new `can()` method, checks if an action can be performed on a resource
    - Many methods now have different signatures

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
