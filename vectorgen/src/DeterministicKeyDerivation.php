<?php
declare(strict_types=1);

namespace FediE2EE\PKD\VectorGen;

use ParagonIE\ConstantTime\{Base64UrlSafe, Binary};
use SodiumException;

use function hash_hmac;
use function hash_hkdf;
use function sodium_crypto_sign_seed_keypair;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_secretkey;

/**
 * Deterministic key derivation for test vectors.
 *
 * Uses HMAC-SHA512 with repository URL as key and test case ID
 * as message to derive keypairs deterministically.
 */
class DeterministicKeyDerivation
{
    private const REPO_URL = 'https://github.com/fedi-e2ee/' .
        'public-key-directory-specification';

    /**
     * Pre-Authentication Encoding function from PASETO spec.
     *
     * @param array<int, string> $pieces
     */
    public static function pae(array $pieces): string
    {
        $output = self::le64(count($pieces));
        foreach ($pieces as $piece) {
            $output .= self::le64(Binary::safeStrlen($piece));
            $output .= $piece;
        }
        return $output;
    }

    /**
     * Little-endian 64-bit encoding.
     */
    public static function le64(int $n): string
    {
        return pack('P', $n);
    }

    /**
     * Derive a seed from test case ID using HMAC-SHA512.
     */
    public static function deriveSeed(string $testCaseId): string
    {
        return hash_hmac(
            'sha512',
            $testCaseId,
            self::REPO_URL,
            true
        );
    }

    /**
     * Derive Ed25519 keypair from test case ID.
     *
     * @throws SodiumException
     * @return array{secret-key: string, public-key: string}
     */
    public static function deriveEd25519Keypair(
        string $testCaseId
    ): array {
        $ikm = self::deriveSeed($testCaseId);
        $seed = hash_hkdf(
            'sha512',
            $ikm,
            32,
            self::pae(['ed25519', $testCaseId])
        );

        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $secretKey = sodium_crypto_sign_secretkey($keypair);
        $publicKey = sodium_crypto_sign_publickey($keypair);

        return [
            'secret-key' => Base64UrlSafe::encodeUnpadded($secretKey),
            'public-key' => Base64UrlSafe::encodeUnpadded($publicKey)
        ];
    }

    /**
     * Derive X25519 keypair (for HPKE) from test case ID.
     *
     * @throws SodiumException
     * @return array{secret-key: string, public-key: string}
     */
    public static function deriveX25519Keypair(
        string $testCaseId
    ): array {
        $ikm = self::deriveSeed($testCaseId);
        $secretKey = hash_hkdf(
            'sha512',
            $ikm,
            32,
            self::pae(['x25519', $testCaseId])
        );

        $publicKey = sodium_crypto_scalarmult_base($secretKey);

        return [
            'secret-key' => Base64UrlSafe::encodeUnpadded($secretKey),
            'public-key' => Base64UrlSafe::encodeUnpadded($publicKey)
        ];
    }

    /**
     * Derive a 256-bit symmetric key from test case ID.
     */
    public static function deriveSymmetricKey(
        string $testCaseId,
        string $purpose
    ): string {
        $ikm = self::deriveSeed($testCaseId);
        return hash_hkdf(
            'sha512',
            $ikm,
            32,
            self::pae(['symmetric', $purpose, $testCaseId])
        );
    }
}
