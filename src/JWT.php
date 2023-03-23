<?php 

namespace Kooriv\JWT;

use Ahc\Jwt\JWT as AhcJWT;
use Kooriv\JWT\Exceptions\Blacklist;

class JWT extends AhcJWT
{
	private \Illuminate\Cache\Repository $cache;
	private bool $blackListStatus;
	private string $blackListPrefix = "JWT_BLACKLIST_";

	function __construct()
	{
		$this->cache = app('cache')->driver();
		$this->blackListStatus = (bool) env('JWT_BLACK_LIST', false);

		$KEY 		= env('JWT_KEY', 'secret');
		$ALGO 		= env('JWT_ALGO', 'HS256');
		$MAX_AGE 	= env('JWT_MAX_AGE', 3600);
		$LEEWAY 	= env('JWT_LEEWAY', 0);

		parent::__construct(key: $KEY, algo: $ALGO, maxAge: $MAX_AGE, leeway: $LEEWAY);
	}

	public function decode(string $token, bool $verify = true): array
	{
		if ($this->blackListStatus && $this->cache->get(key: $this->blackListPrefix . $token)) {
			throw new Blacklist;
		}

		return parent::decode(token: $token, verify: $verify);
	}

	public function refresh(string $token): string
	{
		$payload = $this->expire(token: $token);
		unset($payload['exp']);

		return $this->encode($payload);
	}

	public function expire(string $token): array
	{
		$payload = $this->decode(token: $token);
		$expireAfter = $payload['exp'] - time();

		if ( $this->blackListStatus && $expireAfter != $this->maxAge ) {
			$this->cache->set(
				key: $this->blackListPrefix . $token, 
				value: $payload, 
				ttl: $payload['exp'] - time()
			);
		}

		return $payload;
	}
}