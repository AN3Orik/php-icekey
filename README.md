# ICE Cipher implementation for PHP
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FAN3Orik%2Fphp-icekey.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FAN3Orik%2Fphp-icekey?ref=badge_shield)

Original source: http://www.darkside.com.au/ice/

# Usage example
```
// ICE Key initialize
$iceKey = new IceKey(0, array(0x11, 0x22, 0x33, 0x44, 0x54, 0x55, 0x66, 0x77));
// Bytes to encrypt
$plainBytes = array(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10);
// Encrypt bytes
$cryptedBytes = iceKey->encrypt($plainBytes);
// And decrypt back
$plainBytes2 = iceKey->decrypt($cryptedBytes);
```

## Install

Install of the library and its dependencies via [Composer](http://getcomposer.org/).

``` bash
composer require an3o/php-icekey
```

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FAN3Orik%2Fphp-icekey.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FAN3Orik%2Fphp-icekey?ref=badge_large)