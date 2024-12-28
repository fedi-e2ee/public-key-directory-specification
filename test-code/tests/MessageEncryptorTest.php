<?php
declare(strict_types=1);
namespace FediE2EE\TestCode\Tests;

use FediE2EE\TestCode\MessageEncryptor;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

/**
 * @covers MessageEncryptor
 */
class MessageEncryptorTest extends TestCase
{
    public function testFunctionality()
    {
        $key = random_bytes(32);
        $crypt = new MessageEncryptor($key);
        $cipher = $crypt->encrypt('foo', 'bar');
        $plain = $crypt->decrypt('foo', $cipher);
        $this->assertSame('bar', $plain);

        try {
            $crypt->decrypt('baz', $cipher);
            $failed = false;
        } catch (\Exception) {
            $failed = true;
        }
        $this->assertTrue($failed, 'Decryption should have failed');
    }

    public function testWithRecentRoot()
    {
        $key = random_bytes(32);
        $recentRoot = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $crypt = new MessageEncryptor($key);
        $cipher = $crypt->encrypt('foo', 'bar', $recentRoot);
        $plain = $crypt->decrypt('foo', $cipher, $recentRoot);
        $this->assertSame('bar', $plain);

        try {
            $crypt->decrypt('foo', $cipher);
            $failed = false;
        } catch (\Exception) {
            $failed = true;
        }
        $this->assertTrue($failed, 'Decryption should have failed without recent root');
    }

}