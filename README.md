Nginx Auth HMAC Module
=============================

Description:
============

The Nginx auth HMAC module enhances the security and functionality of the standard secure link module.  
Secure token is created using secure HMAC construction with an arbitrary hash algorithm supported by OpenSSL, e.g.:
`blake2b512`, `blake2s256`, `gost`, `md4`, `md5`, `mdc2`, `rmd160`, `sha1`, `sha224`, `sha256`,
`sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `sha384`, `sha512`, `sha512-224`, `sha512-256`, `shake128`, `shake256`, `sm3`.

Furthermore, secure token is created as described in RFC2104, that is,
`H(secret_key XOR opad,H(secret_key XOR ipad, message))` instead of a simple `MD5(secret_key,message, expire)`.

Installation:
=============

You'll need to re-compile Nginx from source to include this module.  
Modify your compile of Nginx by adding the following directive (modified to suit your path of course):

Static module (built-in nginx binary)

    ./configure --add-module=/absolute/path/to/ngx_http_auth_hmac_module

Dynamic nginx module `ngx_http_auth_hmac_module.so` module

    ./configure --with-compat --add-dynamic-module=/absolute/path/to/ngx_http_auth_hmac_module

Build Nginx

    make
    make install

Usage:
======

Message to be hashed is defined by `auth_hmac_message`, `secret_key` is given by `auth_hmac_secret`, and hashing algorithm H is defined by `auth_hmac_algorithm`.

For improved security, the time or a timestamp (depending on the date format specified by format parameter) should be appended to the message to be hashed.

It is possible to create links with limited lifetime. This is defined by optional parameters range_start or range_end. If the expiration period is not specified, a link has the unlimited lifetime.

Configuration example for server side.

```nginx
location ^~ /files/ {
    # Enables the feature, if disabled, $auth_hmac will always be empty
    auth_hmac on;

    # Set the time value used for checking.
    # You can set the expiration time range, the format of the time value, and the time zone of the time value
    auth_hmac_check_time $arg_ts range_end=$arg_e format=%s;

    # Set the token value used for checking
    # Available formats are hex (default), base64, base64url and bin
    auth_hmac_check_token $arg_st format=hex;

    # Secret key
    auth_hmac_secret "my_secret_key";

    # Message to be verified
    auth_hmac_message "$uri|$arg_ts|$arg_e";

    # Cryptographic hash function to be used
    auth_hmac_algorithm sha256;

    # In production environment, we should not reveal to potential attacker
    # why hmac authentication has failed
    # - If the hash is incorrect then $auth_hmac is a NULL string.
    # - If the hash is correct and the link has not expired then $auth_hmac is "1".
    if ($auth_hmac != "1") {
        return 403;
    }

    rewrite ^/files/(.*)$ /files/$1 break;
}
```

Application side should use a standard hash_hmac function to generate hash, which then needs to be hex or base64url encoded. Example in Perl below.

#### Variable $data contains secure token, timestamp in ISO 8601 format, and expiration period in seconds

```nginx
perl_set $secure_token '
    sub {
        use Digest::SHA qw(hmac_sha256_base64);
        use POSIX qw(strftime);

        my $now = time();
        my $secret = "my_very_secret_key";
        my $expire = 60;
        my $tz = strftime("%z", localtime($now));
        $tz =~ s/(\d{2})(\d{2})/$1:$2/;
        my $timestamp = strftime("%Y-%m-%dT%H:%M:%S", localtime($now)) . $tz;
        my $r = shift;
        my $data = $r->uri;

        # hex
        my $string_to_hash = $data . "|" . $timestamp . "|" . $expire;
        my $digest_binary = hmac_sha256($string_to_hash, $secret);
        my $digest = unpack("H*", $digest_binary);

        # base64url
        # my $digest = hmac_sha256_base64($data . "|" . $timestamp . "|" . $expire,  $secret);
        # $digest =~ tr(+/)(-_);

        $data = "st=" . $digest . "&ts=" . $timestamp . "&e=" . $expire;
        return $data;
    }
';
```

A similar function in PHP

```php
$secret = 'my_very_secret_key';
$expire = 60;
$algo = 'sha256';
$timestamp = date('c');
$unixtimestamp = time();
$stringtosign = "/files/top_secret.pdf|{$unixtimestamp}|{$expire}";
// hex
$hashmac = bin2hex(hash_hmac($algo, $stringtosign, $secret, true));
// base64url
// $hashmac = base64_encode(hash_hmac($algo, $stringtosign, $secret, true));
// $hashmac = strtr($hashmac, '+/', '-_');
// $hashmac = str_replace('=', '', $hashmac);
$host = $_SERVER['HTTP_HOST'];
$loc = "https://{$host}/files/top_secret.pdf?st={$hashmac}&ts={$unixtimestamp}&e={$expire}";
```

Using Unix timestamp in Node.js

```javascript
const crypto = require("crypto");
const secret = 'my_very_secret_key';
const expire = 60;
const unixTimestamp = Math.round(Date.now() / 1000.);
const stringToSign = `/files/top_secret.pdf|${unixTimestamp}|${expire}`;
// hex
const hashmac = crypto.createHmac('sha256', secret).update(stringToSign).digest('hex')
// base64url
// const hashmac = crypto.createHmac('sha256', secret).update(stringToSign).digest('base64')
//       .replace(/=/g, '')
//       .replace(/\+/g, '-')
//       .replace(/\//g, '_');
const loc = `https://host/files/top_secret.pdf?st=${hashmac}&ts=${unixTimestamp}&e=${expire}`;
```

Bash version

```shell
#!/bin/bash

SECRET="my_super_secret"
TIME_STAMP="$(date -d "today + 0 minutes" +%s)";
EXPIRES="3600"; # seconds
URL="/file/my_secret_file.txt"
ST="$URL|$TIME_STAMP|$EXPIRES"
# hex
TOKEN="$(echo -n $ST | openssl dgst -sha256 -hmac $SECRET | awk '{print $1}')"
# Base64url
# TOKEN="$(echo -n $ST | openssl dgst -sha256 -hmac $SECRET -binary | openssl base64 | tr +/ -_ | tr -d =)"

echo "http://127.0.0.1$URL?st=$TOKEN&ts=$TIME_STAMP&e=$EXPIRES"
```

Embedded Variables
==================
* `$auth_hmac` - If the hash is correct and the link has not expired then $secure_link_hash is "1". Otherwise, it is null.


Contributing:
=============

Git source repositories: http://github.com/hanadalee/ngx_http_auth_hmac_module/tree/master

Please feel free to fork the project at GitHub and submit pull requests or patches.
