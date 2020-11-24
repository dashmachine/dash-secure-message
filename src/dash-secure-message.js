// imports
const Dashcore = require('dashcore-lib');
const ECIES = require('bitcore-ecies-dash');


const crypto = require('crypto');
const debug = require('debug')('server:debug'); //not used - uncomment console.log for testing


/**
 * DashSecureMessage performs ECIES encryption & decryption and Double SHA256 Hashing. Note the class contains only static methods so you do not have to call the contructor, i.e. use DashSecureMessage.encrypt, not new DashSecureMessage() 
 * @class DashSecureMessage
 * @hideconstructor
 * @example
 * <!-- Usage in HTML file -->
 * 
 * <script src="dash-secure-message-lib.js" type="text/javascript"></script>
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
 * @example
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

    
 * 
 */
module.exports = class DashSecureMessage {

    /**
     * 
     * @static encrypt Encrypt a message for specific user
     * 
     * @param {string} senderPrivateKey The private key of the Dash User sending the message
     * @param {string} message message to encrypt
     * @param {object} recipientPublicKey The public key for the Identity of the Dash User receiveing the message
     * @returns {string} The encrypted message
     */
    static encrypt(senderPrivateKey, message, recipientPublicKey, options) {
        //console.log(`encrypting following message:\n${message}`);
        let publicKeyToUse;
        publicKeyToUse = recipientPublicKey;

        const binary = options.binary || false;
        let delimiter;
        if (binary) {
            delimiter = options.delimiter || '  ';
        }

        try {
            const doEncryption = function () {
                //Convert Keys to DER format using Dashcore Library
                const recipientPublicKeyBuffer = Buffer.from(publicKeyToUse, 'base64')
                //console.log(`recipientPublicKeyBuffer: ${recipientPublicKeyBuffer}`)
                const recipientPublicKeyFromBuffer = new Dashcore.PublicKey(recipientPublicKeyBuffer)
                //console.log(`recipientPublicKeyFromBuffer ${recipientPublicKeyFromBuffer}`)
                const signingKey = new Dashcore.PrivateKey(senderPrivateKey)

                //sender encrypts
                const sender = ECIES()
                    .privateKey(signingKey)
                    .publicKey(recipientPublicKeyFromBuffer);

                const encrypted = sender.encrypt(message);

                //console.log("ENCRYPTED BYTES", encrypted)

                if (!binary) {
                    //return B64 of the stringified JSON of the reult buffer
                    const encryptedToB64 = Buffer.from(JSON.stringify(encrypted)).toString('base64');
                    //console.log(`encrypted: ${encryptedToB64}`);

                    return encryptedToB64;
                }
                else {
                    return encrypted;
                }
            }

            if (Array.isArray(recipientPublicKey)) {
                if (binary) {
                    return joinBuffers(recipientPublicKey.map(k => {
                        publicKeyToUse = k;
                        return doEncryption();
                    }), delimiter)

                }
                else {
                    //return an array containing encrypted msg for each public key
                    return recipientPublicKey.map(k => {
                        publicKeyToUse = k;
                        return [k, doEncryption()];
                    })
                }
            }
            else {
                return doEncryption();
            }

        } catch (e) {
            //console.log(`encrypt error: ${e}`)
            throw e;
        }

    }


    /**
     * 
     * @static decrypt Decrypt a message for a user
     * 
     * @param {string} recipientPrivateKey The private key of the Dash User receiving the message
     * @param {string} encryptedMessage The encrypted message to decrypt
     * @param {object} senderPublicKey The public key for the Identity of the Dash User sending the message
     * @returns {string} The decrypted message
     */
    static decrypt(recipientPrivateKey, encryptedMessage, senderPublicKey, options) {

        try {
            let toDecrypt;

            let messageToDecrypt;

            if (options.useOutput) {

            }
            else {
                messageToDecrypt = encryptedMessage;
            }
            let inputIsArray;
            let arrayToDecrypt;

            const binary = options.binary || false;
            let delimiter;
            if (binary) {
                delimiter = options.delimiter || '  ';
            }


            const doDecryption = function () {
                let senderPublicKeyToUse;
                if (options.useOutput) {

                }
                else {
                    senderPublicKeyToUse = senderPublicKey;
                }
                const senderPublicKeyBuffer = Buffer.from(senderPublicKeyToUse, 'base64')
                //console.log(`senderPublicKeyBuffer: ${senderPublicKeyBuffer}`)
                const senderPublicKeyFromBuffer = new Dashcore.PublicKey(senderPublicKeyBuffer)
                //console.log(`senderPublicKeyFromBuffer ${senderPublicKeyFromBuffer}`)

                const decryptingKey = new Dashcore.PrivateKey(recipientPrivateKey)

                const recipient = ECIES()
                    .privateKey(decryptingKey)
                    .publicKey(senderPublicKeyFromBuffer);


                if (!binary) {
                    toDecrypt = Buffer.from(JSON.parse(Buffer.from(messageToDecrypt, 'base64').toString()).data)
                }

                else {

                    toDecrypt = messageToDecrypt
                }


                const decrypted = recipient.decrypt(toDecrypt);
                //console.log(`decrypted: ${decrypted}`);

                return Buffer.from(decrypted).toString();

            }



            if (binary) {
                //TODO: is this single or multiple messages
                const bsplit = require('buffer-split');
                const delimBuffer = Buffer.from(delimiter);
                //console.log("delimBuffer", delimBuffer);
                const splitResult = bsplit(encryptedMessage, delimBuffer);
                const numBuffers = splitResult.length;
                //console.log("number of buffers", numBuffers);
                if (numBuffers > 1) {
                    inputIsArray = true;
                    arrayToDecrypt = splitResult
                }
            }

            if (Array.isArray(encryptedMessage)) {
                inputIsArray = true;
                arrayToDecrypt = encryptedMessage;
            }

            if (inputIsArray) {
                //brute force attempt to decrypt for each message with this key
                const result = arrayToDecrypt.map(m => {
                    messageToDecrypt = m;
                    //console.log("attemping to decrypt:", m);
                    try {

                        return [m, doDecryption()];

                    }
                    catch (e) {
                        //console.log("error decrypting this message with the private key");
                        return null
                    }

                });
                return result.filter(r => r != null);
            }
            else {
                return doDecryption();
            }




        } catch (e) {
            //console.log(`decrypt error: ${e}`)
            throw e;
        }

    }
    /**
   * @static hash Double SHA Hash a message and return digest as hex 
   * 
   * @param {string} message full message to be hashed 
   * @returns {string} The hex digestof the  message
   * 
   */
    static hash(message) {
        //console.log(`hashing message ${message}`);
        try {
            const hash1 = crypto
                .createHash("sha256")
                .update(message)
                .digest("base64");

            const digest = crypto
                .createHash("sha256")
                .update(hash1)
                .digest("base64");

            //console.log(`digest: ${digest}`);

            return digest;
        } catch (e) {
            //console.log(`hash error: ${e}`)
            throw e;
        }
    }


    /**
     * @static verify Double SHA Hash a message and compare against input 
     * 
     * @param {string} message full message to be hashed 
     * @param {string} digest digest to compare
     * @@returns {boolean} The boolean result of message verification  
     */
    static verify(message, digest) {
        //console.log(`verifying message ${message} against digest ${digest}`);
        try {
            const hashed = this.hash(message);
            if (hashed === digest) {
                return true;
            }
            else {
                return false;
            }
        } catch (e) {
            //console.log(`hash error: ${e}`)
            throw e;
        }
    }

    /**
     * 
     * @static generateEntropy generates random entropy (a dash address)
     * 
     * @returns {string} A dash address for use as entropy
     */
    static generateEntropy() {
        try {
            return new Dashcore.PublicKey(new Dashcore.PrivateKey()).toAddress().toString();
        } catch (e) {
            //console.log(`generateEntropy error: ${e}`)
            throw e;
        }

    }

}

function joinBuffers(buffers, delimiter = '  ') {
    let d = Buffer.from(delimiter);
    //console.log("delimiter as bytes", d);
    //console.log("buffers", buffers)
    return buffers.reduce((prev, b) => Buffer.concat([prev, d, b]));
}