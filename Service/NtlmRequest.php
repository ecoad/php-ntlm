<?php
namespace Loune\NtlmRequestBundle\Service;

use Symfony\Component\DependencyInjection\ContainerInterface;

//
// I have adapted the code written by the author below to work as a Symfony2 Bundle - Elliot Coad
//
//

// loune 25/3/2006, 22/08/2009, 20/09/2009
// For more information see:
// http://siphon9.net/loune/2009/09/ntlm-authentication-in-php-now-with-ntlmv2-hash-checking/
//

/*

php ntlm authentication library
Version 1.2

Copyright (c) 2009-2010 Loune Lam

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Usage:

	include('ntlm.php');

	protected function get_ntlm_user_hash($user) {
		$userdb = array('loune'=>'test', 'user1'=>'password');

		if (!isset($userdb[strtolower($user)]))
			return false;
		return ntlm_md4($this->ntlm_utf8_to_utf16le($userdb[strtolower($user)]));
	}

	session_start();
	$auth = ntlm_prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local", "get_ntlm_user_hash");

	if ($auth['authenticated']) {
		print "You are authenticated as $auth[username] from $auth[domain]/$auth[workstation]";
	}

To logout, use the code:

	$this->ntlm_unset_auth();

*/

class NtlmRequest {
    /**
     * @var ContainerInteface $container
     */
    protected $container;

	protected $ntlm_verifyntlmpath = '/sbin/verifyntlm';

	public function __construct(ContainerInterface $container) {
		$this->container = $container;
	}

	protected function ntlm_utf8_to_utf16le($str) {
		//$result = "";
		//for ($i = 0; $i < strlen($str); $i++)
		//    $result .= $str[$i]."\0";
		//return $result;
		return iconv('UTF-8', 'UTF-16LE', $str);
	}

	protected function ntlm_md4($s) {
		if (function_exists('mhash'))
			return mhash(MHASH_MD4, $s);
		return pack('H*', hash('md4', $s));
	}

	protected function ntlm_av_pair($type, $utf16) {
		return pack('v', $type).pack('v', strlen($utf16)).$utf16;
	}

	protected function ntlm_field_value($msg, $start, $decode_utf16 = true) {
		$len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
		$off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
		$result = substr($msg, $off, $len);
		if ($decode_utf16) {
			//$result = str_replace("\0", '', $result);
			$originalResult = $result;
			$result = iconv('UTF-16LE', 'UTF-8', $result);
		}
			return $result;
	}

	protected function ntlm_hmac_md5($key, $msg) {
		$blocksize = 64;
		if (strlen($key) > $blocksize)
			$key = pack('H*', md5($key));

		$key = str_pad($key, $blocksize, "\0");
		$ipadk = $key ^ str_repeat("\x36", $blocksize);
		$opadk = $key ^ str_repeat("\x5c", $blocksize);
		return pack('H*', md5($opadk.pack('H*', md5($ipadk.$msg))));
	}

	protected function ntlm_get_random_bytes($length) {
		$result = "";
		for ($i = 0; $i < $length; $i++) {
			$result .= chr(rand(0, 255));
		}
		return $result;
	}

	protected function ntlm_get_challenge_msg($msg, $challenge, $targetname, $domain, $computer, $dnsdomain, $dnscomputer) {
		$domain = $this->ntlm_field_value($msg, 16);
		$ws = $this->ntlm_field_value($msg, 24);
		$tdata = $this->ntlm_av_pair(2, $this->ntlm_utf8_to_utf16le($domain)).$this->ntlm_av_pair(1, $this->ntlm_utf8_to_utf16le($computer)).$this->ntlm_av_pair(4, $this->ntlm_utf8_to_utf16le($dnsdomain)).$this->ntlm_av_pair(3, $this->ntlm_utf8_to_utf16le($dnscomputer))."\0\0\0\0\0\0\0\0";
		$tname = $this->ntlm_utf8_to_utf16le($targetname);

		$msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
			pack('vvV', strlen($tname), strlen($tname), 48). // target name len/alloc/offset
			"\x01\x02\x81\x00". // flags
			$challenge. // challenge
			"\x00\x00\x00\x00\x00\x00\x00\x00". // context
			pack('vvV', strlen($tdata), strlen($tdata), 48 + strlen($tname)). // target info len/alloc/offset
			$tname.$tdata;
		return $msg2;
	}

	protected function ntlm_verify_hash($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob, $get_ntlm_user_hash) {
		$logger = $this->container->get('logger');
		$logger->info('NTLM header username: "' . $user .'"');
		$userProvider = $this->container->get('user.provider');

		if (!$user = $userProvider->loadUserByUsername($user)) {
			return false;
		}

		$password = $userProvider->decryptPassword($user->getPassword());
		$md4hash = $this->ntlm_md4($this->ntlm_utf8_to_utf16le($password));

		$ntlmv2hash = $this->ntlm_hmac_md5($md4hash, $this->ntlm_utf8_to_utf16le(strtoupper($user->getUsername()).$domain));
		$blobhash = $this->ntlm_hmac_md5($ntlmv2hash, $challenge.$clientblob);

		return ($blobhash == $clientblobhash);
	}

	protected function ntlm_parse_response_msg($msg, $challenge, $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback) {
		$user = $this->ntlm_field_value($msg, 36);
		$domain = $this->ntlm_field_value($msg, 28);
		$workstation = $this->ntlm_field_value($msg, 44);
		$ntlmresponse = $this->ntlm_field_value($msg, 20, false);
		//$blob = "\x01\x01\x00\x00\x00\x00\x00\x00".$timestamp.$nonce."\x00\x00\x00\x00".$tdata;
		$clientblob = substr($ntlmresponse, 16);
		$clientblobhash = substr($ntlmresponse, 0, 16);

		// print bin2hex($msg)."<br>";

		if (!$this->$ntlm_verify_hash_callback($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob, $get_ntlm_user_hash_callback)) {
			throw new \Symfony\Component\Security\Core\Exception\AuthenticationException('NTLM hash failed');
		}
		return array('authenticated' => true, 'username' => $user, 'domain' => $domain, 'workstation' => $workstation);
	}

	protected function ntlm_unset_auth() {
		//unset ($_SESSION['_ntlm_auth']);
		$this->container->get('session')->set('_ntlm_auth', null);
	}

	public function ntlm_prompt($targetname, $domain, $computer, $dnsdomain, $dnscomputer, $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback = 'ntlm_verify_hash', $failmsg = "<h1>Authentication Required</h1>") {

		$auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;
		if ($auth_header == null && function_exists('apache_request_headers')) {
			$headers = apache_request_headers();
			$auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : null;
		}

		//if (isset($_SESSION['_ntlm_auth']))
		//	return $_SESSION['_ntlm_auth'];

		if ($this->container->get('session')->get('_ntlm_auth')) {
			$auth = $this->container->get('session')->get('_ntlm_auth');
			return $auth['username'];
		}

		// post data retention, looks like not needed
		/*if ($_SERVER['REQUEST_METHOD'] == 'POST') {
			$_SESSION['_ntlm_post_data'] = $_POST;
		}*/

		if (!$auth_header) {
			header('HTTP/1.1 401 Unauthorized');
			header('WWW-Authenticate: NTLM');
			echo $failmsg;
			exit;
		}

		if (substr($auth_header,0,5) == 'NTLM ') {
			$msg = base64_decode(substr($auth_header, 5));
			if (substr($msg, 0, 8) != "NTLMSSP\x00") {
				//unset($_SESSION['_ntlm_post_data']);
				$this->container->get('session')->set('_ntlm_post_data', null);
				die('NTLM error header not recognised');
			}

			if ($msg[8] == "\x01") {
				//$_SESSION['_ntlm_server_challenge'] = $this->ntlm_get_random_bytes(8);
				$this->container->get('session')->set('_ntlm_server_challenge', $this->ntlm_get_random_bytes(8));

				header('HTTP/1.1 401 Unauthorized');
				//$msg2 = $this->ntlm_get_challenge_msg($msg, $_SESSION['_ntlm_server_challenge'], $targetname, $domain, $computer, $dnsdomain, $dnscomputer);
				$msg2 = $this->ntlm_get_challenge_msg($msg, $this->container->get('session')->get('_ntlm_server_challenge'), $targetname, $domain, $computer, $dnsdomain, $dnscomputer);
				header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
				//print bin2hex($msg2);
				exit;
			}
			else if ($msg[8] == "\x03") {
				//$auth = $this->ntlm_parse_response_msg($msg, $_SESSION['_ntlm_server_challenge'], $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback);
				$auth = $this->ntlm_parse_response_msg($msg, $this->container->get('session')->get('_ntlm_server_challenge'), $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback);

				//unset($_SESSION['_ntlm_server_challenge']);
				$this->container->get('session')->set('_ntlm_server_challenge', null);

				if (!$auth['authenticated']) {
					header('HTTP/1.1 401 Unauthorized');
					header('WWW-Authenticate: NTLM');
					//unset($_SESSION['_ntlm_post_data']);
					exit;
				}

				$this->container->get('session')->set('_ntlm_auth', $auth);
				return $auth['username'];
			}
		}
	}
}