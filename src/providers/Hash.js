var sha3 = require('js-sha3');

exports.hashTable = {
    "KECCAK224": function(msg) {
        return sha3.keccak224(msg);
    },
    "KECCAK256": function(msg) {
        return sha3.keccak256(msg);
    },
    "KECCAK384": function(msg) {
        return sha3.keccak384(msg);
    },
    "KECCAK512": function(msg) {
        return sha3.keccak512(msg);
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

  