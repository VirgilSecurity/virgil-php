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
use Virgil\Crypto\Core\Enum\HashAlgorithms;
use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKeyCollection;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\Crypto\VirgilCrypto;
use Virgil\CryptoTests\Utils\CompatibilityDataProvider;
use Virgil\CryptoTests\Utils\ExceptionLogger;

/**
 * Class CryptoCompatibilityTests
 *
 * @package Virgil\Tests
 */
class CryptoCompatibilityTest extends TestCase
{
    use ExceptionLogger;

    const string JSON_DATA = "/data/crypto_compatibility_data.json";

    /**
     * @return VirgilCrypto
     * @throws Exception
     */
    private function getCrypto(): VirgilCrypto
    {
        return new VirgilCrypto(null, true);
    }

    /**
     * @return CompatibilityDataProvider
     */
    private function getDataProvider(): CompatibilityDataProvider
    {
        return new CompatibilityDataProvider(__DIR__.self::JSON_DATA);
    }

    #[group]
    public function test001CheckNumberOfTestsInJSON()
    {
        self::assertEquals(8, $this->getDataProvider()->getNumberOfTests());
    }

    #[group]
    public function test002DecryptFromSingleRecipientShouldDecrypt()
    {
        try {
            $dict = $this->getDataProvider()->getTestData("encrypt_single_recipient");

            $privateKeyStr = $dict["private_key"];
            $privateKeyData = base64_decode($privateKeyStr);

            $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

            $originalDataStr = $dict["original_data"];

            $cipherDataStr = $dict["cipher_data"];
            $cipherData = base64_decode($cipherDataStr);

            $decryptedData = $this->getCrypto()->decrypt($cipherData, $privateKey);
            $decryptedDataStr = base64_encode($decryptedData);

            self::assertEquals($decryptedDataStr, $originalDataStr);
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    #[group]
    public function test003DecryptFromMultipleRecipientsShouldDecypt()
    {
        try {
            $dict = $this->getDataProvider()->getTestData("encrypt_multiple_recipients");

            $privateKeys = [];

            foreach ($dict["private_keys"] as $privateKeyStr) {
                $privateKeyData = base64_decode($privateKeyStr);
                $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

                $privateKeys[] = $privateKey;
            }

            self::assertTrue(count($privateKeys) > 0);

            $originalDataStr = $dict["original_data"];

            $cipherDataStr = $dict["cipher_data"];
            $cipherData = base64_decode($cipherDataStr);

            foreach ($privateKeys as $privateKey) {
                $decryptedData = $this->getCrypto()->decrypt($cipherData, $privateKey);
                $decryptedDataStr = base64_encode($decryptedData);

                self::assertEquals($decryptedDataStr, $originalDataStr);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    #[group]
    public function test004DecryptAndVerifySingleRecipientShouldDecryptAndVerify()
    {
        try {
            $dict = $this->getDataProvider()->getTestData("sign_and_encrypt_single_recipient");

            $privateKeyStr = $dict["private_key"];
            $privateKeyData = base64_decode($privateKeyStr);

            $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

            $publicKey = $this->getCrypto()->extractPublicKey($privateKey);
            $pkl = new VirgilPublicKeyCollection($publicKey);

            $originalDataStr = $dict["original_data"];
            $originalData = base64_decode($originalDataStr);

            $cipherDataStr = $dict["cipher_data"];
            $cipherData = base64_decode($cipherDataStr);

            $decryptedData = $this->getCrypto()->decryptAndVerify($cipherData, $privateKey, $pkl);

            self::assertEquals($originalData, $decryptedData);
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    #[grozup]
    public function test005DecryptAndVerifyMultipleRecipientsShouldDecryptAndVerify()
    {
        try {
            $dict = $this->getDataProvider()->getTestData("sign_and_encrypt_multiple_recipients");

            $privateKeys = [];

            foreach ($dict["private_keys"] as $privateKeyStr) {
                $privateKeyData = base64_decode($privateKeyStr);
                $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

                $privateKeys[] = $privateKey;
            }

            self::assertTrue(count($privateKeys) > 0);

            $originalDataStr = $dict["original_data"];

            $cipherDataStr = $dict["cipher_data"];
            $cipherData = base64_decode($cipherDataStr);

            $signerPublicKey = $this->getCrypto()->extractPublicKey($privateKeys[0]);
            $pkl = new VirgilPublicKeyCollection($signerPublicKey);

            foreach ($privateKeys as $privateKey) {
                $decryptedData = $this->getCrypto()->decryptAndVerify($cipherData, $privateKey, $pkl);
                $decryptedDataStr = base64_encode($decryptedData);

                self::assertEquals($decryptedDataStr, $originalDataStr);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    #[group]
    public function test006GenerateSignatureShouldBeEqual()
    {
        try {
            $dict = $this->getDataProvider()->getTestData("generate_signature");

            $privateKeyStr = $dict["private_key"];
            $privateKeyData = base64_decode($privateKeyStr);

            $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

            $publicKey = $this->getCrypto()->extractPublicKey($privateKey);

            $originalDataStr = $dict["original_data"];
            $originalData = base64_decode($originalDataStr);

            $signature = $this->getCrypto()->generateSignature($originalData, $privateKey);
            $signatureStr = base64_encode($signature);

            $originalSignatureStr = $dict["signature"];
            $originalSignature = base64_decode($originalSignatureStr);

            $res = $this->getCrypto()->verifySignature($originalSignature, $originalData, $publicKey);

            self::assertTrue($res);
            self::assertEquals($originalSignatureStr, $signatureStr);
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    #[group]
    public function test007DecryptAndVerifyMultipleSignersShouldDecryptAndVerify()
    {
        try {
            $dict = $this->getDataProvider()->getTestData("sign_and_encrypt_multiple_signers");

            $privateKeyStr = $dict["private_key"];
            $privateKeyData = base64_decode($privateKeyStr);

            $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

            $pkl = new VirgilPublicKeyCollection();

            foreach ($dict["public_keys"] as $publicKeyStr) {
                $publicKeyData = base64_decode($publicKeyStr);
                $publicKey = $this->getCrypto()->importPublicKey($publicKeyData);

                $pkl->addPublicKey($publicKey);
            }

            $originalDataStr = $dict["original_data"];

            $cipherDataStr = $dict["cipher_data"];
            $cipherData = base64_decode($cipherDataStr);

            $decryptedData = $this->getCrypto()->decryptAndVerify($cipherData, $privateKey, $pkl);
            $decryptedDataStr = base64_encode($decryptedData);

            self::assertEquals($decryptedDataStr, $originalDataStr);
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    #[group]
    public function test008GenerateEd25519UsingSeedShouldMatch()
    {
        try {
            $dict = $this->getDataProvider()->getTestData("generate_ed25519_using_seed");

            $seedStr = $dict["seed"];
            $seed = base64_decode($seedStr);

            $keyPair = $this->getCrypto()->generateKeyPairUsingSeed($seed);

            $privateKeyStr = $dict["private_key"];
            $publicKeyStr = $dict["public_key"];
            $privateKeyData = base64_decode($privateKeyStr);
            $publicKeyData = base64_decode($publicKeyStr);

            $a1 = $this->getCrypto()->exportPrivateKey($keyPair->getPrivateKey());
            self::assertEquals($a1, $privateKeyData);

            $b1 = $this->getCrypto()->exportPublicKey($keyPair->getPublicKey());
            self::assertEquals($b1, $publicKeyData);
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }

    #[group]
    public function test009SignThenEncryptShouldMatch()
    {
        try {
            $dict = $this->getDataProvider()->getTestData("auth_encrypt");

            $privateKey1Str = $dict["private_key1"];
            $privateKey2Str = $dict["private_key2"];
            $publicKey1Str = $dict["public_key1"];
            $dataSha512Str = $dict["data_sha512"];
            $cipherDataStr = $dict["cipher_data"];

            $senderPublicKey = $this->getCrypto()->importPublicKey(base64_decode($publicKey1Str));
            $senderPrivateKey = $this->getCrypto()->importPrivateKey(base64_decode($privateKey1Str))->getPrivateKey();

            $receiverKeyPair = $this->getCrypto()->importPrivateKey(base64_decode($privateKey2Str));
            $senderPkl = new VirgilPublicKeyCollection($senderPublicKey);
            $receiverPkl = new VirgilPublicKeyCollection($receiverKeyPair->getPublicKey());

            $expectedDataHash = base64_decode($dataSha512Str);
            $cipherData = base64_decode($cipherDataStr);

            $data = $this->getCrypto()->authDecrypt($cipherData, $receiverKeyPair->getPrivateKey(), $senderPkl);
            $actualDataHash = $this->getCrypto()->computeHash($data, HashAlgorithms::SHA512());

            self::assertEquals($actualDataHash, $expectedDataHash);

            try {
                // Wrong validation key
                $res1 = $this->getCrypto()->authDecrypt($cipherData, $receiverKeyPair->getPrivateKey(), $receiverPkl);
                self::assertEmpty($res1);
            } catch (Exception $e) {
                self::assertTrue($e instanceof VirgilCryptoException);
            }

            try {
                // Wrong decryption key
                $res2 = $this->getCrypto()->authDecrypt($cipherData, $senderPrivateKey, $senderPkl);
                self::assertEmpty($res2);
            } catch (Exception $e) {
                self::assertTrue($e instanceof VirgilCryptoException);
            }
        } catch (Exception $exception) {
            self::fail($this->logException($exception));
        }
    }
}
