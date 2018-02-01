<?php

namespace Virgil\Crypto;


class VirgilPFSResponderPrivateInfo
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($identityPrivateKey, $longTermPrivateKey = null, $oneTimePrivateKey = null)
    {
        if (is_resource($identityPrivateKey) &&
            get_resource_type($identityPrivateKey) === '_p_virgil__crypto__pfs__VirgilPFSResponderPrivateInfo'
        ) {
            $this->_cPtr = $identityPrivateKey;

            return;
        }
        switch (func_num_args()) {
            case 2:
                $this->_cPtr = new_VirgilPFSResponderPrivateInfo($identityPrivateKey, $longTermPrivateKey);
                break;
            default:
                $this->_cPtr = new_VirgilPFSResponderPrivateInfo(
                    $identityPrivateKey,
                    $longTermPrivateKey,
                    $oneTimePrivateKey
                );
        }
    }


    function __set($var, $value)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        $this->_pData[$var] = $value;
    }


    function __get($var)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return $this->_pData[$var];
    }


    function __isset($var)
    {
        if ($var === 'thisown') {
            return true;
        }

        return array_key_exists($var, $this->_pData);
    }


    function getIdentityPrivateKey()
    {
        $r = VirgilPFSResponderPrivateInfo_getIdentityPrivateKey($this->_cPtr);
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSPrivateKey($r);
        }

        return $r;
    }


    function getLongTermPrivateKey()
    {
        $r = VirgilPFSResponderPrivateInfo_getLongTermPrivateKey($this->_cPtr);
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSPrivateKey($r);
        }

        return $r;
    }


    function getOneTimePrivateKey()
    {
        $r = VirgilPFSResponderPrivateInfo_getOneTimePrivateKey($this->_cPtr);
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSPrivateKey($r);
        }

        return $r;
    }
}