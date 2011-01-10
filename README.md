# Bonafide Authentication

Flexible authentication system supporting multiple/portable password hashing schemes.

# Basic Usage

Configuration (`config/bonafide.php`):

    return array(

        // Group name, multiple configuration groups are supported
        'default' => array(

            // Multiple mechanisms can be added for versioned passwords, etc
            'mechanisms' => array(

                // Bonafide ships with a HMAC hashing mechanism
                array('hash', array(
                    // Hash prefix, must be unique for every mechanism!
                    'prefix' => NULL,

                    // Hash type to use when calling hash_hmac()
                    'type' => 'sha256',

                    // Shared secret HMAC key
                    'key' => 'put your shared secret key here!',
                )),
            ),
        ),
    );

To get the hash of a plaintext password:

    $hash = Bonafide::instance()->hash($password);

To a plaintext password against a hashed password:

    if (Bonafide::instance()->check($password, $hash))
    {
        // Authentication successful, store the user in session, etc
    }

## Salting and Strengthening

To increase the security of your hashes, it is highly recommended that you configure a per-user salt and iteration count. These can be passed to `Bonafide::hash` and `Bonafide::check`:

    $hash = $bonafide->hash($password, $salt, $iterations);

    if ($bonafide->check($password, $hash, $salt, $iterations))
    {
        // Auth success
    }

If you are doing this within a model, it might look like this:

    public function update_password($password)
    {
        $this->password = Bonafide::instance()
            ->hash($password, $this->salt, $this->iterations);

        return $this->save();
    }

    public function check_password($password)
    {
        return Bonafide::instance()
            ->check($password, $this->password, $this->salt, $this->iterations);
    }