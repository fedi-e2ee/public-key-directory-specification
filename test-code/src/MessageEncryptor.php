<?php
namespace FediE2EE\TestCode;

use Exception;

class MessageEncryptor
{
    protected const string CURRENT_VERSION = "\x01";
    protected const string INFO_ENCRYPT = 'FediE2EE-v1-Compliance-Encryption-Key';
    protected const string INFO_AUTH = 'FediE2EE-v1-Compliance-Message-Auth-Key';
    protected const string PLAIN_COMMIT = 'FediE2EE-v1-Compliance-Plaintext-Commitment';
    protected const string SALT_PREFIX = 'FediE2EE-v1-Compliance-Salt-Prekey';
    protected const string PLAIN_SALT_PREFIX = 'FE2EEPKDv1';

    public function __construct(#[\SensitiveParameter] private string $ikm)
    {}

    public static function plaintextCommitment(
        string $salt,
        string $attributeName,
        string $value,
        ?string $recentRoot = null
    ): string {
        if (is_null($recentRoot)) {
            $recentRoot = str_repeat("\0", 3);
        }
        $l = self::len($recentRoot) . $recentRoot .
             self::len($attributeName) . $attributeName .
             self::len($value) . $value;
        return  sodium_crypto_pwhash(
            32,
            $l,
            $salt,
            3,
            16777216,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
    }

    /**
     * Calculate a salt for plaintext commitments.
     *
     * @param string $header
     * @param string $randomness
     * @param string $attributeName
     * @param string $recentRoot
     * @return string
     */
    protected static function commitmentSalt(
        string $header,
        string $randomness,
        string $attributeName,
        string $recentRoot,
    ): string {
        $st = hash_init('sha512');
        hash_update($st, self::SALT_PREFIX);
        hash_update($st, $header);
        hash_update($st, $randomness);
        hash_update($st, $recentRoot);
        hash_update($st, self::len($attributeName));
        hash_update($st, $attributeName);
        $raw = hash_final($st, true);

        // We only need the final 16 bytes:
        return substr($raw, 48, 16);
    }

    /**
     * @throws Exception
     */
    public function encrypt(
        string $attributeName,
        string $plaintext,
        ?string $recentRoot = null
    ): string {
        if (is_null($recentRoot)) {
            $recentRoot = str_repeat("\0", 3);
        }
        $h = self::CURRENT_VERSION;
        $r = random_bytes(32);
        $tmp = hash_hkdf('sha512', $this->ikm, 48, self::INFO_ENCRYPT . $h . $r . $attributeName);
        $encKey = substr($tmp, 0, 32);
        $n = substr($tmp, 32, 16);
        $salt = self::commitmentSalt($h, $attributeName, $r, $recentRoot);
        $macKey = hash_hkdf('sha512', $this->ikm, 32, self::INFO_AUTH . $h . $r . $attributeName);
        $Q = self::plaintextCommitment($salt, $attributeName, $plaintext, $recentRoot);
        $c = openssl_encrypt(
            $plaintext,
            'aes-256-ctr',
            $encKey,
            OPENSSL_NO_PADDING | OPENSSL_RAW_DATA,
            $n
        );
        if (!is_string($c)) {
            throw new Exception('Encryption failure');
        }
        // `h || r || n || len(a) || a || len(c) || c || len(Q) || Q`
        $t = substr(
            hash_hmac(
                'sha512',
                $h . $r . self::len($attributeName) . $attributeName . self::len($c) . $c . self::len($Q) . $Q,
                $macKey,
                true
            ),
            32,
            32
        );
        return $h . $r . $Q . $t. $c ;
    }

    /**
     * @throws Exception
     */
    public function decrypt(
        string $attributeName,
        string $ciphertext,
        ?string $recentRoot = null
    ): string {
        $len = strlen($ciphertext);
        if ($len < 97) {
            throw new Exception('Message is too short');
        }
        if (is_null($recentRoot)) {
            $recentRoot = str_repeat("\0", 3);
        }
        $h = substr($ciphertext, 0, 1);
        $r = substr($ciphertext, 1, 32);
        $Q = substr($ciphertext, 33, 32);
        $t = substr($ciphertext, 65, 32);
        $c = substr($ciphertext, 97);

        if (!hash_equals($h, self::CURRENT_VERSION)) {
            throw new Exception('Invalid version prefix');
        }
        $macKey = hash_hkdf('sha512', $this->ikm, 32, self::INFO_AUTH . $h . $r . $attributeName);
        $t2 = substr(
            hash_hmac(
                'sha512',
                $h . $r . self::len($attributeName) . $attributeName . self::len($c) . $c . self::len($Q) . $Q,
                $macKey,
                true
            ),
            32,
            32
        );
        if (!hash_equals($t2, $t)) {
            throw new Exception('Invalid authentication tag');
        }
        $tmp = hash_hkdf('sha512', $this->ikm, 48, self::INFO_ENCRYPT . $h . $r . $attributeName);
        $encKey = substr($tmp, 0, 32);
        $n = substr($tmp, 32, 16);
        $p = openssl_encrypt(
            $c,
            'aes-256-ctr',
            $encKey,
            OPENSSL_NO_PADDING | OPENSSL_RAW_DATA,
            $n
        );
        $salt = self::commitmentSalt($h, $attributeName, $r, $recentRoot);
        $Q2 = self::plaintextCommitment($salt, $attributeName, $p, $recentRoot);
        if (!hash_equals($Q2, $Q)) {
            throw new Exception('Invalid plaintext commitment');
        }
        return $p;
    }

    protected static function len(string $x): string
    {
        $len = strlen($x);
        return pack('J', $x);
    }
}