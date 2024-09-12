<?php
/**
 * Copyright (C) 2015-2024 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Virgil\Crypto\Core\Enum;

use MyCLabs\Enum\Enum;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\CryptoWrapper\Foundation\AlgId;

/**
 * Class keeps list of key pair types constants.
 *
 * Class KeyPairType
 *
 * @method static KeyPairType ED25519
 * @method static KeyPairType CURVE25519
 * @method static KeyPairType SECP256R1
 * @method static KeyPairType RSA2048
 * @method static KeyPairType RSA4096
 * @method static KeyPairType RSA8192
 *
 * @package Virgil\Crypto\Core\Enum
 */
class KeyPairType extends Enum
{
    private const string ED25519 = "ED25519";
    private const string CURVE25519 = "CURVE25519";
    private const string SECP256R1 = "SECP256R1";
    private const string RSA2048 = "RSA2048";
    private const string RSA4096 = "RSA4096";
    private const string RSA8192 = "RSA8192";

    /**
     * @param KeyPairType $keyPairType
     *
     * @return null|int
     */
    public function getRsaBitLen(KeyPairType $keyPairType): ?int
    {
        return match ((string)$keyPairType) {
            (string)$keyPairType::RSA2048() => 2048,
            (string)$keyPairType::RSA4096() => 4096,
            (string)$keyPairType::RSA8192() => 8192,
            default => null,
        };
    }

    /**
     * @param int $bitLen
     *
     * @return KeyPairType
     * @throws VirgilCryptoException
     */
    public static function getRsaKeyType(int $bitLen): KeyPairType
    {
        return match ($bitLen) {
            2048 => KeyPairType::RSA2048(),
            4096 => KeyPairType::RSA4096(),
            8192 => KeyPairType::RSA8192(),
            default => throw new VirgilCryptoException(VirgilCryptoError::UNSUPPORTED_RSA_LENGTH()),
        };
    }

    /**
     * @param AlgId $algId
     *
     * @return KeyPairType
     * @throws VirgilCryptoException
     */
    public static function getFromAlgId(AlgId $algId): KeyPairType
    {
        return match ((string)$algId) {
            (string)$algId::ED25519() => KeyPairType::ED25519(),
            (string)$algId::CURVE25519() => KeyPairType::CURVE25519(),
            (string)$algId::SECP256R1() => KeyPairType::SECP256R1(),
            (string)$algId::RSA() => throw new VirgilCryptoException(
                VirgilCryptoError::RSA_SHOULD_BE_CONSTRUCTED_DIRECTLY()
            ),
            default => throw new VirgilCryptoException(VirgilCryptoError::UNKNOWN_ALG_ID()),
        };
    }

    /**
     * @param KeyPairType $keyPairType
     *
     * @return AlgId
     * @throws VirgilCryptoException
     */
    public function getAlgId(KeyPairType $keyPairType): AlgId
    {
        return match ((string)$keyPairType) {
            (string)$keyPairType::ED25519() => AlgId::ED25519(),
            (string)$keyPairType::CURVE25519() => AlgId::CURVE25519(),
            (string)$keyPairType::SECP256R1() => AlgId::SECP256R1(),
            (string)$keyPairType::RSA2048(), (string)$keyPairType::RSA4096(), (string)$keyPairType::RSA8192(
            ) => AlgId::RSA(),
            default => throw new VirgilCryptoException(VirgilCryptoError::UNKNOWN_ALG_ID()),
        };
    }
}
