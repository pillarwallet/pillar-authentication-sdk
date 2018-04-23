var EC = require("elliptic").ec;
const BN = require('bn.js');
var hashProvider = require("./src/providers/Hash.js");
var ec = new EC('secp256k1');


   /** 
    * Sign a payload
    * @method sign
    * @param  {Object} data Payload to be signed
    * @param  {String} privateKey Signer's private key
    * @param  {String} hash Hash algorithm
    * @return {String} DER signature
    */

exports.sign = (data, privateKey, hash) => {
    var key = ec.keyFromPrivate(privateKey,"hex");
    var digest  =  hashProvider.hashTable[hash](JSON.stringify(data));
    var signature =  ec.sign(digest, key, "hex").toDER();
    return signature;
}

/** 
    * Signature verification 
    * @method verify
    * @param  {Object} data Signed payload (including signature) 
    * @param  {String} publicKey Signer's public key 
    * @param  {String} hash Hash algorithm
    * @return {Bool} Bool
    */
exports.verify = (data, publicKey, hash) =>{    
    var key = ec.keyFromPublic(publicKey, 'hex');
    var signature = data.signature;
    delete data['signature'];
    var digest  =  hashProvider.hashTable[hash](JSON.stringify(data));
    return key.verify(digest,signature);
}

