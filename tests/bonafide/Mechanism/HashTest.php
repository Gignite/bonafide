<?php defined('SYSPATH') or die('No direct script access.');

/**
 * Tests for Bonafide's Pbkdf2 mechanism
 *
 * @group kohana
 *
 * @package    Bonafide
 * @category   Tests
 * @author     Woody Gilk <woody.gilk@kohanaframework.org>
 * @copyright  (c) 2011 Woody Gilk
 * @license    MIT
 */
class Bonafide_Mechanism_HashTest extends Kohana_Unittest_TestCase {

	/**
	 * These tests all use sha1. See RFC2104 for details on these tests.
	 *
	 * @link http://www.ietf.org/rfc/rfc2104.txt
	 * @return array
	 */
	public function provider_hash()
	{
		return array(
			// password, salt, iterations, expected
			array('password', 'salt', '1', '1f1077faf082b465bd2c90be232b4b0a6412e3e8'),
			array('password', 'salt', '10', '3f6f6cd06d693335bb0aab27de16a65c49a3cb99'),
			array('password', 'salt', '1000', '3e5d539ef94c8bbda580ebed535e26a64058d10d'),
			array('password', 'tals', '1', 'b15da43751fcbb92052ff0793dff620f0bfcfc76'),
			// With unicode
			array('ᴘᴀꜱꜱᴡᴏʀᴅ', 'salt', '1', 'f967bfb76ee5736ee97379c3f525f97ac186a855'),
			// With null bytes
			array("pass\0word", "\0salt", '100', '121345ccf35ebbe7feddc94ac9170d3d0cd03bfe'),
		);
	}

	/**
	 * Vector tests for the Bonafide's Hash mechanism.
	 *
	 * @test
	 * @dataProvider provider_hash
	 * @param string $password     Plaintext password
	 * @param string $salt         Salt
	 * @param int    $iterations   Iterations
	 * @param string $expected     Expected value
	 */
	public function test_hash($password, $salt, $iterations, $expected)
	{
		$config = array(
			'type' => 'sha1',
			'key' => 'Unit testing for Bonafide',
		);

		$hash = Bonafide::mechanism('hash', $config)->hash($password, $salt, $iterations);

		$this->assertSame($hash, $expected);
	}

} // End Test Bonafide_Mechanism_Hash

