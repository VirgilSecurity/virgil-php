<?php
/**
 * Copyright (C) 2015-2020 Virgil Security Inc.
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Virgil\CryptoTests;

use Exception;
use PHPUnit\Framework\TestCase;
use Virgil\Crypto\Core\Enum\KeyPairType;
use Virgil\Crypto\Core\Stream;
use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKeyCollection;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\Crypto\VirgilCrypto;
use Virgil\CryptoTests\Utils\ExceptionLogger;

/**
 * Class CryptoTests
 *
 * @package Virgil\Tests
 */
class CryptoTest extends TestCase
{
    use ExceptionLogger;

    /**
     * @param array $files
     */
    private function unlinkFiles(array $files): void
    {
        foreach ($files as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkKeyGeneration(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $keyPair = $crypto->generateKeyPair($keyPairType);

        $a1 = $keyPair->getPrivateKey()->getIdentifier();
        $a2 = $keyPair->getPublicKey()->getIdentifier();

        self::assertEquals($a1, $a2);
    }

    /**
     * group
     */
    public function test01KeyGenerationGenerateOneKeyShouldSucceed()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [
                KeyPairType::CURVE25519(),
                KeyPairType::ED25519(),
                KeyPairType::SECP256R1(),
                KeyPairType::RSA2048()
            ];

            foreach ($keyTypes as $keyType) {
                $this->checkKeyGeneration($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkKeyImport(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $keyPair = $crypto->generateKeyPair($keyPairType);
        $data1 = $crypto->exportPrivateKey($keyPair->getPrivateKey());
        $privateKey = $crypto->importPrivateKey($data1);

        $a1 = $keyPair->getPrivateKey()->getIdentifier();
        $a2 = $privateKey->getIdentifier();

        self::assertEquals($a1, $a2);

        $data2 = $crypto->exportPublicKey($keyPair->getPublicKey());
        $publicKey = $crypto->importPublicKey($data2);

        $b1 = $keyPair->getPublicKey()->getIdentifier();
        $b2 = $publicKey->getIdentifier();

        self::assertEquals($b1, $b2);
    }

    #[group]
    public function test02KeyImportAllKeysShouldMatch()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [
                KeyPairType::CURVE25519(),
                KeyPairType::ED25519(),
                KeyPairType::SECP256R1(),
                KeyPairType::RSA2048()
            ];

            foreach ($keyTypes as $keyType) {
                $this->checkKeyImport($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkEncryption(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);

        $data = "test";

        $pkl = new VirgilPublicKeyCollection($keyPair1->getPublicKey());

        $encryptedData = $crypto->encrypt($data, $pkl);
        $decryptedData = $crypto->decrypt($encryptedData, $keyPair1->getPrivateKey());

        self::assertEquals($data, $decryptedData);

        try {
            $tempRes = $crypto->decrypt($encryptedData, $keyPair2->getPrivateKey());
            self::assertEmpty($tempRes);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }
    }

    #[group]
    public function test03EncryptionSomeDataShouldMatch()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [
                KeyPairType::CURVE25519(),
                KeyPairType::ED25519(),
                KeyPairType::SECP256R1(),
                KeyPairType::RSA2048()
            ];

            foreach ($keyTypes as $keyType) {
                $this->checkEncryption($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkSignature(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);

        $rawData = "test";

        $signature = $crypto->generateSignature($rawData, $keyPair1->getPrivateKey());

        $res1 = $crypto->verifySignature($signature, $rawData, $keyPair1->getPublicKey());
        self::assertTrue($res1);

        try {
            $res2 = $crypto->verifySignature($signature, $rawData, $keyPair2->getPublicKey());
            self::assertEmpty($res2);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }
    }

    #[group]
    public function test04SignatureSomeDataShouldVerify()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

            foreach ($keyTypes as $keyType) {
                $this->checkSignature($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkSignAndEncrypt(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $data = "test";

        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);
        $keyPair3 = $crypto->generateKeyPair($keyPairType);

        $pkl = new VirgilPublicKeyCollection($keyPair1->getPublicKey(), $keyPair2->getPublicKey());

        $encrypted = $crypto->signAndEncrypt($data, $keyPair1->getPrivateKey(), $pkl);

        $pkl1 = new VirgilPublicKeyCollection($keyPair1->getPublicKey(), $keyPair2->getPublicKey());
        $pkl2 = new VirgilPublicKeyCollection($keyPair3->getPublicKey());

        $decrypted = $crypto->decryptAndVerify($encrypted, $keyPair2->getPrivateKey(), $pkl1);

        self::assertEquals($data, $decrypted);

        try {
            $res1 = $crypto->decryptAndVerify($encrypted, $keyPair3->getPrivateKey(), $pkl1);
            self::assertEmpty($res1);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }

        try {
            $res2 = $crypto->decryptAndVerify($encrypted, $keyPair2->getPrivateKey(), $pkl2);
            self::assertEmpty($res2);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }
    }

    #[group]
    public function test05SignAndEncryptSomeDataShouldDecryptAndVerify()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

            foreach ($keyTypes as $keyType) {
                $this->checkSignAndEncrypt($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkStreamSign(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);

        $testFileUrl = __DIR__ . "/data/testData.txt";
        $encTestFileUrl = __DIR__ . "/data/testData_enc.txt";

        $this->unlinkFiles([$encTestFileUrl]);

        $stream = new Stream($testFileUrl, $encTestFileUrl, $crypto->getChunkSize());
        $signature = $crypto->generateStreamSignature($stream, $keyPair1->getPrivateKey());

        $verifyStream1 = new Stream($testFileUrl, $encTestFileUrl, $crypto->getChunkSize());
        $verifyStream2 = new Stream($testFileUrl, $encTestFileUrl, $crypto->getChunkSize());

        $res1 = $crypto->verifyStreamSignature($signature, $verifyStream1, $keyPair1->getPublicKey());
        self::assertTrue($res1);

        try {
            $res2 = $crypto->verifyStreamSignature($signature, $verifyStream2, $keyPair2->getPublicKey());
            self::assertEmpty($res2);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }

        $this->unlinkFiles([$encTestFileUrl]);
    }

    #[group]
    public function test06SignStreamFileShouldVerify()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

            foreach ($keyTypes as $keyType) {
                $this->checkStreamSign($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkStreamEncryption(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);

        $testFileUrl = __DIR__ . "/data/testData.txt";

        $encTestFileUrl = __DIR__ . "/data/testData_encrypted.txt";
        $decTestFileUrl = __DIR__ . "/data/testData_decrypted.txt";

        $this->unlinkFiles([$encTestFileUrl, $decTestFileUrl]);

        $stream = new Stream($testFileUrl, $encTestFileUrl, $crypto->getChunkSize());

        $rawData = file_get_contents($testFileUrl);

        $pkl = new VirgilPublicKeyCollection($keyPair1->getPublicKey());
        $encrypt = $crypto->encrypt($stream, $pkl);

        $stream1 = new Stream($encTestFileUrl, $decTestFileUrl, $crypto->getChunkSize());
        $stream2 = new Stream($encTestFileUrl, $decTestFileUrl, $crypto->getChunkSize());

        $decrypt = $crypto->decrypt($stream1, $keyPair1->getPrivateKey());

        $decryptedData = file_get_contents($decTestFileUrl);

        self::assertEquals($rawData, $decryptedData);

        try {
            $res = $crypto->decrypt($stream2, $keyPair2->getPrivateKey());
            self::assertEmpty($res);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }

        $this->unlinkFiles([$encTestFileUrl, $decTestFileUrl]);
    }

    #[group]
    public function test07EncryptStreamFileShouldDecrypt()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [
                KeyPairType::CURVE25519(),
                KeyPairType::ED25519(),
                KeyPairType::SECP256R1(),
                KeyPairType::RSA2048()
            ];

            foreach ($keyTypes as $keyType) {
                $this->checkStreamEncryption($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkGenerateKeyUsingSeed(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $seed = $crypto->generateRandomData(32);

        $keyId = $crypto->generateKeyPairUsingSeed($seed)->getIdentifier();

        for ($i = 0; $i < 5; $i++) {
            $keyPair = $crypto->generateKeyPairUsingSeed($seed);

            $a1 = $keyPair->getPrivateKey()->getIdentifier();
            self::assertEquals($a1, $keyId);

            $a2 = $keyPair->getPublicKey()->getIdentifier();
            self::assertEquals($a1, $a2);
        }
    }

    #[group]
    public function test08GenerateKeyUsingSeedFixedSeedShouldMatch()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [
                KeyPairType::CURVE25519(),
                KeyPairType::ED25519(),
                KeyPairType::SECP256R1(),
                KeyPairType::RSA2048()
            ];

            foreach ($keyTypes as $keyType) {
                $this->checkGenerateKeyUsingSeed($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkKeyExportImport(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $keyPair = $crypto->generateKeyPair($keyPairType);
        $publicKeyData = $crypto->exportPublicKey($keyPair->getPublicKey());
        $privateKeyData = $crypto->exportPrivateKey($keyPair->getPrivateKey());

        $publicKey = $crypto->importPublicKey($publicKeyData);
        $privateKey = $crypto->importPrivateKey($privateKeyData)->getPrivateKey();

        $pkl = new VirgilPublicKeyCollection($publicKey);
        $res = $crypto->signAndEncrypt("", $privateKey, $pkl);

        self::assertTrue(!is_null($res));
        self::assertTrue(is_string($res));
    }

    #[group]
    public function test10ImportExportKeyRandomKeyShouldMatch()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

            foreach ($keyTypes as $keyType) {
                $this->checkKeyExportImport($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkAuthEncrypt(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);
        $keyPair3 = $crypto->generateKeyPair($keyPairType);

        $data = "test";

        $pkl1 = new VirgilPublicKeyCollection($keyPair2->getPublicKey());

        $encrypted = $crypto->authEncrypt($data, $keyPair1->getPrivateKey(), $pkl1);

        $pkl2 = new VirgilPublicKeyCollection($keyPair1->getPublicKey());
        $decrypted = $crypto->authDecrypt($encrypted, $keyPair2->getPrivateKey(), $pkl2);

        self::assertEquals($data, $decrypted);

        try {
            $res1 = $crypto->authDecrypt($encrypted, $keyPair3->getPrivateKey(), $pkl2);
            self::assertEmpty($res1);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }

        try {
            $pkl3 = new VirgilPublicKeyCollection($keyPair3->getPublicKey());
            $res2 = $crypto->authDecrypt($encrypted, $keyPair2->getPrivateKey(), $pkl3);
            self::assertEmpty($res2);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }
    }

    #[group]
    public function test11AuthEncryptRandomDataShouldMatch()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

            foreach ($keyTypes as $keyType) {
                $this->checkAuthEncrypt($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkAuthEncryptStream(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);
        $keyPair3 = $crypto->generateKeyPair($keyPairType);

        $pkl = new VirgilPublicKeyCollection($keyPair1->getPublicKey(), $keyPair2->getPublicKey());
        $pkl3 = new VirgilPublicKeyCollection($keyPair3->getPublicKey());

        $testFileUrl = __DIR__ . "/data/testData.txt";
        $encTestFileUrl = __DIR__ . "/data/testData_encrypted.txt";
        $decTestFileUrl = __DIR__ . "/data/testData_decrypted.txt";

        $this->unlinkFiles([$encTestFileUrl, $decTestFileUrl]);

        $rawData = file_get_contents($testFileUrl);
        $stream = new Stream($testFileUrl, $encTestFileUrl, filesize($testFileUrl));

        $encrypt = $crypto->authEncrypt($stream, $keyPair1->getPrivateKey(), $pkl);

        $stream1 = new Stream($encTestFileUrl, $decTestFileUrl, $crypto->getChunkSize());
        $stream2 = new Stream($encTestFileUrl, $decTestFileUrl, $crypto->getChunkSize());
        $stream3 = new Stream($encTestFileUrl, $decTestFileUrl, $crypto->getChunkSize());

        $decrypt = $crypto->authDecrypt($stream1, $keyPair1->getPrivateKey(), $pkl);
        $decryptedData = file_get_contents($decTestFileUrl);

        self::assertEquals($rawData, $decryptedData);

        try {
            $res1 = $crypto->authDecrypt($stream2, $keyPair3->getPrivateKey(), $pkl);
            self::assertEmpty($res1);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }

        try {
            $res2 = $crypto->authDecrypt($stream3, $keyPair2->getPrivateKey(), $pkl3);
            self::assertEmpty($res2);
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }

        $this->unlinkFiles([$encTestFileUrl, $decTestFileUrl]);
    }

    #[group]
    public function test12AuthEncryptStreamShouldMatch()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

            foreach ($keyTypes as $keyType) {
                $this->checkAuthEncryptStream($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkAuthEncryptDeprecated(VirgilCrypto $crypto, KeyPairType $keyPairType): void
    {
        $data = "test";

        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);

        $pkl1 = new VirgilPublicKeyCollection($keyPair1->getPublicKey());
        $pkl2 = new VirgilPublicKeyCollection($keyPair2->getPublicKey());

        $encrypted1 = $crypto->authEncrypt($data, $keyPair1->getPrivateKey(), $pkl2);
        $encrypted2 = $crypto->signAndEncrypt($data, $keyPair1->getPrivateKey(), $pkl2);

        $decrypted1 = $crypto->authDecrypt($encrypted1, $keyPair2->getPrivateKey(), $pkl1, true);
        $decrypted2 = $crypto->authDecrypt($encrypted2, $keyPair2->getPrivateKey(), $pkl1, true);

        self::assertEquals($data, $decrypted1);
        self::assertEquals($data, $decrypted2);
    }

    #[group]
    public function test13AuthEncryptDeprecatedShouldWork()
    {
        try {
            $crypto = new VirgilCrypto();

            $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

            foreach ($keyTypes as $keyType) {
                $this->checkAuthEncryptDeprecated($crypto, $keyType);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }
}
