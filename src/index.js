const BN = require('bn.js');
var hashProvider = require("./providers/Hash.js");
var curveProvider = require("./providers/Curve.js");


   /** 
    * Sign a payload
    * @method sign
    * @param  {Object} data Payload to be signed
    * @param  {String} privateKey Signer's private key
    * @param  {Object} type Signature type { curve: curve (string), hash: hash algorithm (string)}
    * @return {String} 64 bytes hex signature
    */

exports.sign = (data, privateKey, type = {curve:"secp256k1", hash:"KECCAK256"}) => {
    type = {
        curve: (type.curve === undefined) ? "secp256k1" : type.curve,
        hash: (type.hash === undefined) ? "KECCAK256" : type.hash
    }
    var ec = curveProvider.curveTable[type.curve]();
    var key = ec.keyFromPrivate(privateKey,"hex");
    var digest  =  hashProvider.hashTable[type.hash](JSON.stringify(data));
    var signature =  ec.sign(digest, key, "hex",  {canonical:true});
    return {
        signature: signature.r.toString("hex", 64) + signature.s.toString("hex", 64),
        recoveryParam: signature.recoveryParam
    }
}

/** 
    * Signature verification 
    * @method verify
    * @param  {Object} data Signed payload (including signature) 
    * @param  {String} publicKey Signer's public key 
    * @param  {Object} type Signature type { curve: curve (string), hash: hash algorithm (string)}
    * @return {Bool} Bool
    */

exports.verify = (data, publicKey, type = {curve:"secp256k1", hash:"KECCAK256"}) => {
    type = {
        curve: (type.curve === undefined) ? "secp256k1" : type.curve,
        hash: (type.hash === undefined) ? "KECCAK256" : type.hash
    }

    var ec = curveProvider.curveTable[type.curve]();
    var key = ec.keyFromPublic(publicKey, 'hex');
    var signature = {
        r: data.signature.slice(0,64),
        s: data.signature.slice(64)
    }
    delete data['signature'];
    var digest  =  hashProvider.hashTable[type.hash](JSON.stringify(data));

    return key.verify(digest, signature);
}
