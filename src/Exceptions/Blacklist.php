<?php 

namespace Kooriv\JWT\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

class Blacklist extends HttpException
{
	public function __construct()
	{
		parent::__construct(
			statusCode: 401,
			message: 'Access was not granted, The sent token is in the blacklist.',
			previous: null,
			headers: [],
			code: 0
		);
	}
}