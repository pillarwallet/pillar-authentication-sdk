//var ethUtil = require("ethereumjs-util");
var EC = require("elliptic").ec;
var hashProvider = require("./src/providers/Hash.js");
var parseProvider = require("./src/providers/Parse.js");
   /** 
    * Register a new wallet on BCX
    * @method sign
    * @param  {Object} data   
    * @param  {String} privateKey
    * @param  {String} hash
    * @return {String}
    */

exports.sign = (data, privateKey, hash) => {
    var ec = new EC('secp256k1');
    var key = ec.keyFromPrivate(privateKey,"hex");
    var digest  =  hashProvider.hashTable[hash](JSON.stringify(data));
    var signature =  ec.sign(digest, key, "hex");
    return  signature.r.toString("hex")+ signature.s.toString("hex") + (signature.recoveryParam);
}
  