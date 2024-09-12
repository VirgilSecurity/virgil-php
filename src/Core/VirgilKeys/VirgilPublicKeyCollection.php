<?php
/**
 * Copyright (C) 2015-2024 Virgil Security Inc.
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

namespace Virgil\Crypto\Core\VirgilKeys;

/**
 * Class VirgilPublicKeyCollection
 *
 * @package Virgil\Crypto\Core\VirgilKeys
 */
class VirgilPublicKeyCollection
{
    /**
     * @var array
     */
    private array $collection = [];

    /**
     * PublicKeyList constructor.
     *
     * @param VirgilPublicKey ...$publicKey
     */
    public function __construct(VirgilPublicKey ...$publicKey)
    {
        if ($publicKey) {
            array_push($this->collection, ...$publicKey);
        }
    }

    /**
     * @param VirgilPublicKey ...$publicKey
     */
    public function addPublicKey(VirgilPublicKey ...$publicKey): void
    {
        array_push($this->collection, ...$publicKey);
    }

    /**
     * @return array
     */
    public function getAsArray(): array
    {
        return $this->collection;
    }

    /**
     * @return VirgilPublicKey
     */
    public function getFirst(): VirgilPublicKey
    {
        return $this->collection[0];
    }

    /**
     * @return int
     */
    public function getAmountOfKeys(): int
    {
        return count($this->collection);
    }

    /**
     * @param VirgilPublicKeyCollection $virgilPublicKeyCollection
     *
     */
    public function addCollection(VirgilPublicKeyCollection $virgilPublicKeyCollection): void
    {
        foreach ($virgilPublicKeyCollection->getAsArray() as $virgilPublicKey) {
            $this->collection[] = $virgilPublicKey;
        }
    }

    /**
     * @return bool
     */
    public function isEmpty(): bool
    {
        return empty($this->collection);
    }
}
