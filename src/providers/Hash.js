var Hashes = require('jshashes');
var sha3 = require('js-sha3');

exports.hashTable = {
    "MD5": function(msg) {
        return new Hashes.MD5().hex(msg);
    },
    "SHA1": function(msg) {
        return new Hashes.SHA1().hex(msg);
    },
    "SHA224": function(msg) {
        return new Hashes.SHA224().hex(msg);
    },
    "SHA256": function(msg) {
        return new Hashes.SHA256().hex(msg);
    },
    "SHA384": function(msg) {
        return new Hashes.SHA384MD5().hex(msg);
    },
    "SHA512": function(msg) {
        return new Hashes.SHA512().hex(msg);
    },
    "RMD160": function(msg) {
        return new Hashes.RMD160().hex(msg);
    },
    "KECCAK224": function(msg) {
        return sha3.keccak224(msg);
    },
    "KECCAK256": function(msg) {
        return sha3.keccak256(msg);;
    },
    "KECCAK384": function(msg) {
        return sha3.keccak384(msg);;
    },
    "KECCAK512": function(msg) {
        return sha3.keccak512(msg);;
    },
    "SHA3_224": function(msg) {
        return sha3.sha3_224(msg);
    },
    "SHA3_256": function(msg) {
        return sha3.sha3_256(msg);
    },
    "SHA3_384": function(msg) {
        return sha3.sha3_384(msg);
    },
    "SHA3_512": function(msg) {
        return sha3.sha3_512(msg);
    },
    "SHAKE128": function(msg) {
        return sha3.shake128(msg,256);
    },
    "SHAKE256": function(msg) {
        return sha3.shake256(msg,512);
    }    
};

  