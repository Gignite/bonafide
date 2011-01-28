<?php defined('SYSPATH') or die('No direct script access.');

/**
 * Tests for Bonafide's bcrypt mechanism
 *
 * @group kohana
 *
 * @package    Bonafide
 * @category   Tests
 * @author     Woody Gilk <woody.gilk@kohanaframework.org>
 * @copyright  (c) 2011 Woody Gilk
 * @license    MIT
 */
class Bonafide_Mechanism_BcryptTest extends Kohana_Unittest_TestCase {

	/**
	 * @return array
	 */
	public function provider_bcrypt()
	{
		return array(
			// password, salt, iterations, expected
			array('password', 'nazf82.KLJSDWEdsmasd12560', '5', '$2a$05$nazf82.KLJSDWEdsmasd1uhgNJEcEgChvQ39Nss4SGjyBCSHRGAM6'),
			// The minimum iterations is 4, this should be expected
			array('password', 'EWECScadsfa239DFwerDXSRW/', '1', '$2a$04$EWECScadsfa239DFwerDXOZA4F1uJ5fm1vcRWgSDsFH3Wq50SELpi'),
			array('password', 'EWECScadsfa239DFwerDXSRW/', '4', '$2a$04$EWECScadsfa239DFwerDXOZA4F1uJ5fm1vcRWgSDsFH3Wq50SELpi'),
			// With unicode
			array('ᴘᴀꜱꜱᴡᴏʀᴅ', 'EWECScadsfa239DFwerDXSRW/', '1', '$2a$04$EWECScadsfa239DFwerDXO5hDSZQ.WdNheBVivD3rXm7.eLTXyPmi'),
			// Salt is padded
			array('password', 'tooshort', '1', '$2a$04$tooshort$$$$$$$$$$$$$.DqDZLdU3zd9uhFbWGe9qmMbxzJPXpAG'),
		);
	}

	/**
	 * Vector tests for the Bonafide's bcrypt mechanism.
	 *
	 * @test
	 * @dataProvider provider_bcrypt
	 * @param string $password     Plaintext password
	 * @param string $salt         Salt
	 * @param int    $iterations   Iterations
	 * @param string $expected     Expected value
	 */
	public function test_bcrypt($password, $salt, $iterations, $expected)
	{
		$config = array(
			'cost' => '4',
		);

		$hash = Bonafide::mechanism('bcrypt', $config)->hash($password, $salt, $iterations);

		$this->assertSame($hash, $expected);
	}

} // End Test Bonafide_Mechanism_Hash

