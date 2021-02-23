<?php

namespace Stilmark\Registry;

use Stilmark\Parse\Out;
use Stilmark\Parse\Str;

class Whois
{

	public static $json;
	public static $supportedTld = ['be', 'ca', 'com', 'io', 'org', 'net', 'se', 'uk', 'us'];

	public static function query($domain, $raw = false)
	{
		$domainName = explode('.', $domain);
		$tld = end($domainName);
		if (!self::isSupportedTld($tld)) {
			return ['TLD not supported'];
		}
		if (self::isValidDomain($domain)) {
			exec('whois -c '.$tld.' '.$domain, $response);
			$response= array_filter(array_map('trim', $response));
			return self::parseResponse($response, $tld, $raw);
		}
	}

	public static function isValidDomain($domain)
	{
		return filter_var($domain, FILTER_VALIDATE_DOMAIN);
	}

	public static function supportedTlds()
	{
		return self::$supportedTld;
	}

	public static function isSupportedTld($tld)
	{
		return (in_array($tld, self::$supportedTld));
	}

	public static function extractDate($line)
	{
		preg_match('/\:[\s|\t]+([a-z0-9\-\:\s]+)$/i', $line, $match);
		if (isset($match[1])) {
			return date('Y-m-d', strtotime(trim($match[1])));
		}
		return false;
	}

	public static function extractStatusCodes($lines = [], $regexp)
	{
		if ($lines) {
			$statusCodes = [];
			foreach($lines AS $line) {
				preg_match($regexp, $line, $match);
				if (isset($match[1])) {
					$statusCodes[] = trim($match[1]);
				}
			}
			return $statusCodes;
		}
		return [];
	}

	public static function extractState($line, $regexp)
	{
		preg_match($regexp, $line, $match);
		if (isset($match[1])) {
			return trim($match[1]);
		}
		return false;
	}

	public static function parseResponse($response, $tld, $raw = false)
	{
		$whois = [];

		if ($raw) {
			$whois['response'] = implode(PHP_EOL, $response);
		}

		switch($tld) {

			case 'be':

				$line = preg_grep ('/^Registered\:/i', $response);
				if ($line && $registered = self::extractDate(current($line))) {
					$whois['Registered'] = $registered;
				}

				$line = preg_grep ('/^Status\:/i', $response);
				if ($line) {
					$regexp = '/\:[\s|\t]+([a-z\s]+)$/i';
					$whois['StatusCodes'] = Whois::extractStatusCodes($line, $regexp);
					if (isset($whois['StatusCodes'])) {
						if (array_intersect(['AVAILABLE'], $whois['StatusCodes'])) {
							$whois['Status'] = 'Deleted';
						}
						if (array_intersect(['ok'], $whois['StatusCodes'])) {
							$whois['Status'] = 'Active';
						}
					}
				}

				break;

			// ICANN compatible Whois
			case 'ca':
			case 'com':
			case 'io':
			case 'net':
			case 'org':
			case 'us':

				$lines = preg_grep ('/^domain status\:/i', $response);
				if ($lines) {
					$regexp = '/[\s|\t]+([a-z\-]+)?[\s]+?[a-z0-9\:\/\#\.]+$/i';
					$whois['StatusCodes'] = Whois::extractStatusCodes($lines, $regexp);
					if ($whois['StatusCodes']) {
						if (array_intersect(['clientHold', 'pendingDelete', 'serverHold', 'redemptionPeriod'], $whois['StatusCodes'])) {
							$whois['Status'] = 'Suspended';
						}
						if (array_intersect(['ok'], $whois['StatusCodes'])) {
							$whois['Status'] = 'Active';
						}
					}
				}

				$noMatch = [
					'ca' => 'not found',
					'com' => 'no match for domain',
					'io' => 'not found',
					'net' => 'no match for domain',
					'org' => 'not found',
					'us' => 'no Data Found',
				];

				$line = preg_grep ('/'.$noMatch[$tld].'/i', $response);
				if ($line) {
					$whois['Status'] = 'Deleted';
				}

				if (!isset($whois['Status'])) {
					$whois['Status'] = 'Active';
				}

				$line = preg_grep ('/^creation date\:/i', $response);
				if ($line && $registered = self::extractDate(current($line))) {
					$whois['Registered'] = $registered;
				}

				$line = preg_grep ('/^registry expiry date\:/i', $response);
				if ($line && $expires = self::extractDate(current($line))) {
					$whois['Expires'] = $expires;
				}
				break;

			case 'se':

				$line = preg_grep ('/^state\:/i', $response);
				$regexp = '/\:[\s|\t]+([a-z]+)$/i';
				if ($line && $state = self::extractState(current($line), $regexp)) {

					if ($state) {
						if ($state == 'deactivated' || $state == 'quarantine') {
							$whois['Status'] = 'Suspended';
						}
						if ($state == 'active') {
							$whois['Status'] = 'Active';
						}
					}
				}

				$line = preg_grep ('/^status\:/i', $response);
				if ($line) {
					$regexp = '/\:[\s|\t]+([a-z\s]+)$/i';
					$whois['StatusCodes'] = Whois::extractStatusCodes($line, $regexp);
				}

				$line = preg_grep ('/not found.$/i', $response);
				if ($line) {
					$whois['Status'] = 'Deleted';
				}

				$line = preg_grep ('/^created\:/i', $response);
				if ($line && $registered = self::extractDate(current($line))) {
					$whois['Registered'] = $registered;
				}

				$line = preg_grep ('/^expires\:/i', $response);
				if ($line && $expires = self::extractDate(current($line))) {
					$whois['Expires'] = $expires;
				}
				break;

			case 'uk':
				$line = preg_grep ('/registration has been SUSPENDED/i', $response);
				if ($line) {
					$whois['Status'] = 'Suspended';
				}

				$line = preg_grep ('/domain name has not been registered/i', $response);
				if ($line) {
					$whois['Status'] = 'Deleted';
				}

				if (!isset($whois['Status'])) {
					$whois['Status'] = 'Active';
				}

				$line = preg_grep ('/^registered on\:/i', $response);
				if ($line && $registered = self::extractDate(current($line))) {
					$whois['Registered'] = $registered;
				}

				$line = preg_grep ('/^expiry date\:/i', $response);
				if ($line && $expires = self::extractDate(current($line))) {
					$whois['Expires'] = $expires;
				}

				break;
		}

		return $whois;
	}
}