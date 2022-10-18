<?php
declare(strict_types=1);

namespace Orbital\Security;

use \Exception;
use \RangeException;
use \Orbital\Env\Env;

abstract class Encryption {

    /**
     * Encrypt a message
     * @param string $message
     * @param string $key
     * @return string
     * @throws RangeException
     */
    public static function encrypt(string $message, string $key = null): string {

        if( is_null($key) ){
            $key = Env::get('ENCRYPTION_SALT');
        }

        if( mb_strlen($key, '8bit') !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES ){
            throw new RangeException('Key is not the correct size (must be 32 bytes).');
        }

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $cipher = base64_encode(
            $nonce.
            sodium_crypto_secretbox(
                $message,
                $nonce,
                $key
            )
        );

        sodium_memzero($message);
        sodium_memzero($key);

        return $cipher;
    }

    /**
     * Decrypt a message
     * @param string $encrypted
     * @param string $key
     * @return string
     * @throws Exception
     */
    public static function decrypt(string $encrypted, string $key = null): string {

        if( is_null($key) ){
            $key = Env::get('ENCRYPTION_SALT');
        }

        $decoded = base64_decode($encrypted);
        $nonce = mb_substr(
            $decoded,
            0,
            SODIUM_CRYPTO_SECRETBOX_NONCEBYTES,
            '8bit'
        );

        $cipherText = mb_substr(
            $decoded,
            SODIUM_CRYPTO_SECRETBOX_NONCEBYTES,
            null,
            '8bit'
        );

        $plain = sodium_crypto_secretbox_open(
            $cipherText,
            $nonce,
            $key
        );

        if( !is_string($plain) ){
            throw new Exception('Invalid MAC.');
        }

        sodium_memzero($cipherText);
        sodium_memzero($key);

        return $plain;
    }

}