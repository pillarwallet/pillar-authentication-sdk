var assert = require('assert');
var auth = require('../');
var curveProvider = require("../src/providers/Curve.js");
var hashProvider = require("../src/providers/Hash.js");
var EC = require("elliptic").ec;
var sha3 = require('js-sha3');

    
describe('Signature', function() {
    it('Should return a specific signature', function() {

        const privateKey = "1234567890123456789012345678901234567890123456789012345678901234";
        const payload = {a: "1"};
        const expectedSignature = "a74b36f7421a52fd7b7857d77082b732a48ba994c8d23a1418650cf4ccdde68f5c8c7e25ec85754300507fea67c7dbe763e3168f0f1858afb1efa1b3ff8907c";

        let signature = auth.sign(payload, privateKey);
        assert.equal(signature, expectedSignature);

      });

    it('Should accept the signature', function() {
      
    const signature = "a74b36f7421a52fd7b7857d77082b732a48ba994c8d23a1418650cf4ccdde68f5c8c7e25ec85754300507fea67c7dbe763e3168f0f1858afb1efa1b3ff8907c";
    const signedPayload = {
        a: "1",
        signature
    };
    const publicKey = "02e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e";
    assert.ok(auth.verify(signedPayload, publicKey));

    });

    it('Should reject the signature', function() {
        
        const signature = "174b36f7421a52fd7b7857d77082b732a48ba994c8d23a1418650cf4ccdde68f5c8c7e25ec85754300507fea67c7dbe763e3168f0f1858afb1efa1b3ff8907c";
        const signedPayload = {
            a: "1",
            signature
        };
        const publicKey = "02e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e";
        assert.ok(!auth.verify(signedPayload, publicKey));
    });
});

describe('Curve', function() {
    it('Should return corresponding elliptic curves', function() {

        const curves = Object.keys(curveProvider.curveTable).length;
        var key;
        for (key = 0; key < curves; key++) {
            var curve = Object.keys(curveProvider.curveTable)[key];
            expect(curveProvider.curveTable[curve]()).toEqual(new EC(curve));
        }
    });
});

describe('Hash', function() {

    it('Should return corresponding digest for each hash function', function() {

        const hashFunctions = Object.keys(hashProvider.hashTable).length;
        var key;
        var message = "hello";
        for (key = 0; key < hashFunctions; key++) {
            
            var hashFunction = Object.keys(hashProvider.hashTable)[key];    
            
            if (hashFunction == "SHAKE128" || hashFunction === "SHAKE256"){ 

                var moduleDigest = hashProvider.hashTable[hashFunction](message,128);
                var expectedDigest = sha3[hashFunction.toLowerCase()](message,128);
                assert.equal(moduleDigest, expectedDigest);
            }
            else{

                var moduleDigest = hashProvider.hashTable[hashFunction](message);
                var expectedDigest = sha3[hashFunction.toLowerCase()](message);
                assert.equal(moduleDigest, expectedDigest);
            }
        }
    })
})