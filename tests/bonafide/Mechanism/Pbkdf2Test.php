<?php defined('SYSPATH') OR die('Kohana bootstrap needs to be included before tests run');

/**
 * Tests for Bonafide's Pbkdf2 mechanism
 *
 * @group kohana
 *
 * @package    Bonafide
 * @category   Tests
 * @license    MIT
 */
Class Bonafide_Pbkdf2Test extends Kohana_Unittest_TestCase
{
	/**
	 * These tests all use sha1. See RFC6070 for details on these tests.
	 *
	 * @link http://www.rfc-editor.org/rfc/rfc6070.txt
	 * @return array
	 */
	public function provider_pbkdf2()
	{
		return array(
			// password, salt, iterations, derived key length, expected output (hex)
			array('password', 'salt', 1,        20, '0c60c80f961f0e71f3a9b524af6012062fe037a6'),
			array('password', 'salt', 2,        20, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'),
			array('password', 'salt', 4096,     20, '4b007901b765489abead49d926f721d065a429c1'),
			// We don't run this one because it slows down the tests too much.
			//array('password', 'salt', 16777216, 20, 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984'),
			array('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25, '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'),
			array("pass\0word", "sa\0lt", 4096, 16, '56fa6aa75548099dcc37d7f03425e0c3'),
		);
	}

	/**
	 * Vector tests for the Bonafide's Pbkdf2 mechanism.
	 *
	 * @test
	 * @dataProvider provider_pbkdf2
	 * @param string $password     Plaintext password
	 * @param string $salt         Salt
	 * @param int    $iterations   Iterations
	 * @param int    $key_length   Key length
	 * @param string $expected     Expected value
	 */
	public function test_pbkdf2($password, $salt, $iterations, $key_length, $expected)
	{
		$config = array(
			'type'  => 'sha1',
			'iterations' => $iterations,
			'length' => $key_length,
		);

		$hash = Bonafide::mechanism('PBKDF2', $config)->hash($password, $salt);

		$this->assertSame(bin2hex(base64_decode($hash)), $expected);
	}
}
