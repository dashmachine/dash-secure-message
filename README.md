# Dash Secure Message library

Cryptographic helper functions for use in Dash Platform dapp samples.

> Note: this is an experimental library to support dapp sample investigation of Dash Platform usage - not for production use.

## Prerequisites

In Node.js:

    const DashSecureMessage = require('dash-secure-message');

In the browser:

    <script src="dash-secure-message-lib.js" type="text/javascript"></script>

**Please see the examples below for sample usage**

## Browser usage

Include the `dash-secure-message-lib.js` script file available from the [releases page](https://github.com/dashmachine/dash-secure-message/releases).

## Nodejs usage

    npm i dash-secure-message

## v1.1 experimental features - multiple and binary outputs/inputs

These are currently experimental features and so not included in the generated documentation below, please report any issues or feedback

### Multiple inputs and outputs

Multiple public keys can be passed to the `Encrypt` function `recipientPublicKey` parameter as an Array. The target `message` will then by encrypted for each key. 

Similarly, multiple messages can be passed to the `encryptedMessage` parameter of the `Decrypt` function, which will use a 'brute force' approach to detrmine whether any of the messages can be decrypted by the `recipientPrivateKey` passed.

The exact return and method signatures depend upon whether the message outputs are encrypted in, or inputs decrypted from, string or binary types, as described below.

### Binary input and output 

By passing a 4th `options` parameter to the `Encrypt` or `Decrypt` functions, with the property `{binary:true}`, the messages can be input and output in binary format (a `Buffer` in nodejs).

A further option `{delimiter: <string>}` can be passed to override the default double-space delimiter `'  '` (or the binary `Buffer<20 20>`) used for delimiting muliple concatinated buffers when the `binary` option is used in conjunction with encrypting for multiple target public keys.

The following examples illustrate the use of these options with single and multiple target recipients.

**String output (no or empty options passed), muliple public key targets**
```
const encryptedForGroup = DashSecureMessage.encrypt(f2f774d88cd8478eb65a3cd3bba2b74ee235465c4d526cda7c9020c6cda416c4, 'test message', ['A2QdE/f4DIpTuxPkGYFQYzqqZ9ytGy0hMwT6ccth17L4', 'A6+8q1NoaYsmuRNzpoNiUMvDpXEBOYG/yMn3qDXjYNLg'], {});
```
Returns an `Array` containing nested `Arrays` where the first field is the public key passed and the second is the resulting encrypted message
e.g.
```
[
  [
    'A2QdE/f4DIpTuxPkGYFQYzqqZ9ytGy0hMwT6ccth17L4',
    'eyJ0eXBlIjoiQnV ... CwxODZdfQ=='
  ],
  [
    'A6+8q1NoaYsmuRNzpoNiUMvDpXEBOYG/yMn3qDXjYNLg',
    'eyJ0eXB ... cwXX0='
  ]
]
```
**String input of mutiple messages**
To attempt to decrypt these messages for one corresponding private key, the are passed as a single-dimension Array of encryptedMessages, e.g.
```
let encryptedGroupMessage = ['eyJ0eXBlIjoiQnV ... CwxODZdfQ==', 'eyJ0eXB ... cwXX0='];
const decrypted = DashSecureMessage.decrypt(privateBob, encryptedGroupMessage, publicAlice, {});
```
**Binary output, muliple public key targets**
If the `{binary:true}` option is passed, a single concatenated `Buffer` is returned (with `Buffer`s of each message delimited by the default `Buffer<20 20>` or `delimiter` option if paased).
e.g.
```
const encryptedForGroup = DashSecureMessage.encrypt(f2f774d88cd8478eb65a3cd3bba2b74ee235465c4d526cda7c9020c6cda416c4, 'test message', ['A2QdE/f4DIpTuxPkGYFQYzqqZ9ytGy0hMwT6ccth17L4', 'A6+8q1NoaYsmuRNzpoNiUMvDpXEBOYG/yMn3qDXjYNLg'], {binary:true});
```
```
<Buffer 03 a4 4f 95 30 55 63 2c ... 146 more bytes>
```
**Binary input of mutiple messages**
The single buffer returned above can be paased to the `Decrypt` function as the `encryptedMessage` parameter
```
const decryptedForGroupBob = DashSecureMessage.decrypt(privateBob, <Buffer 03 a4 4f 95 30 55 63 2c ... 146 more bytes>, publicAlice, options);
```
Any messages which can be decrypted by Bob's private key in this example will be returned in an `Array` of `Array`s, where the first field is the binary value of the encrypted message, and the second field is the string value of the decrypted message, eg
```
[
  [
    <Buffer 03 a4 4f 95 30 b2 cf 4d 70 35 6a 81 53 f8 46 d9 7f... 47 more bytes>,
    'test'
  ]
]
```

### Documentation

<!-- Generated by documentation.js. Update this documentation by updating the source code. -->

##### Table of Contents

-   [DashSecureMessage](#dashsecuremessage)
    -   [Examples](#examples)
-   [encrypt](#encrypt)
    -   [Parameters](#parameters)
-   [decrypt](#decrypt)
    -   [Parameters](#parameters-1)
-   [hash](#hash)
    -   [Parameters](#parameters-2)
-   [verify](#verify)
    -   [Parameters](#parameters-3)
-   [generateEntropy](#generateentropy)

#### DashSecureMessage

DashSecureMessage performs ECIES encryption & decryption and Double SHA256 Hashing. Note the class contains only static methods so you do not have to call the contructor, i.e. use DashSecureMessage.encrypt, not new DashSecureMessage()

##### Examples

```javascript
<!-- Usage in HTML file -->

<script src="dash-secure-message-lib.js" type="text/javascript"></script>
<script>
const senderPrivateKey = 'e930702ff1dbe78e1d827831e6e29a71264030fbbf5b08154b6cc954aebc011a'
const message = 'hello';
const recipientPublicKey = 'Av1kEA/QGhPA9bP2BlbYrf8RhTqAeU2SdL7OHOXJg/Ve'
const recipientPrivateKey = 'b28aa82d1af0f4548b606897ef376b2035187a70528b203f0604f74f43bc3418'
const senderPublicKey = 'A+KHq0TSgvILh/Bg6eHn7K/y7tvu/uxXjJIRSsqgZlZC'
console.log(`Encrypting message "${message}"...`);
const encrypted = DashSecureMessage.encrypt(senderPrivateKey, message, recipientPublicKey);
console.dir(encrypted);
console.log(`Decrypting result message "${message}"...`);
const decrypted = DashSecureMessage.decrypt(recipientPrivateKey, encrypted, senderPublicKey);
console.dir(decrypted);
console.log(`Hashing message "${message}"...`);
const digest = DashSecureMessage.hash(message);
console.dir(digest);
console.log(`Verifying hash...`);
const verifies = DashSecureMessage.verify(message, digest);
console.dir(verifies)
const entropy = DashSecureMessage.generateEntropy();
console.log(`entropy: ${entropy}`);

</script>
```

```javascript
//use in nodejs
const DashSecureMessage = require("dash-secure-message")

const senderPrivateKey = 'e930702ff1dbe78e1d827831e6e29a71264030fbbf5b08154b6cc954aebc011a'
const message = 'hello';
const recipientPublicKey = 'Av1kEA/QGhPA9bP2BlbYrf8RhTqAeU2SdL7OHOXJg/Ve'
const recipientPrivateKey = 'b28aa82d1af0f4548b606897ef376b2035187a70528b203f0604f74f43bc3418'
const senderPublicKey = 'A+KHq0TSgvILh/Bg6eHn7K/y7tvu/uxXjJIRSsqgZlZC'
console.log(`Encrypting message "${message}"...`);
const encrypted = DashSecureMessage.encrypt(senderPrivateKey, message, recipientPublicKey);
console.dir(encrypted);
console.log(`Decrypting result message "${message}"...`);
const decrypted = DashSecureMessage.decrypt(recipientPrivateKey, encrypted, senderPublicKey);
console.dir(decrypted);
console.log(`Hashing message "${message}"...`);
const digest = DashSecureMessage.hash(message);
console.dir(digest);
console.log(`Verifying hash...`);
const verifies = DashSecureMessage.verify(message, digest);
console.dir(verifies)
const entropy = DashSecureMessage.generateEntropy();
console.log(`entropy: ${entropy}`);
```

#### encrypt

##### Parameters

-   `senderPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The private key of the Dash User sending the message
-   `message` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** message to encrypt
-   `recipientPublicKey` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** The public key for the Identity of the Dash User receiveing the message

Returns **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The encrypted message

#### decrypt

##### Parameters

-   `recipientPrivateKey` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The private key of the Dash User receiving the message
-   `encryptedMessage` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The encrypted message to decrypt
-   `senderPublicKey` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** The public key for the Identity of the Dash User sending the message

Returns **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The decrypted message

#### hash

##### Parameters

-   `message` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** full message to be hashed

Returns **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The hex digestof the  message

#### verify

##### Parameters

-   `message` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** full message to be hashed
-   `digest` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** digest to compare

#### generateEntropy

Returns **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** A dash address fro use as entropy

### License

[MIT License](LICENSE)

# Development

To develop this library:

-   clone the repository and change to project directory 


    git clone  https://github.com/dashmachine/dash-secure-message.git && cd dash-secure-message

The source file is `src/dash-secure-message.js`

-   build output


    npm run build

-   test with webpack dev server


    npm start

-   update documentation (requires npm documentation package installed globally:  `npm i -g documentation`)

Update the Documentation section of the README.md file  

    npm run docs:readme
