var assert = require('assert');
var auth = require('../');
var curveProvider = require("../src/providers/Curve.js");
var hashProvider = require("../src/providers/Hash.js");
var EC = require("elliptic").ec;

    
describe('Signature', function() {
    it('Should return a specific signature', function() {

        const privateKey = "1234567890123456789012345678901234567890123456789012345678901234";
        const payload = {a: "1"};
        const expectedSignature = "a74b36f7421a52fd7b7857d77082b732a48ba994c8d23a1418650cf4ccdde68f05c8c7e25ec85754300507fea67c7dbe763e3168f0f1858afb1efa1b3ff8907c";

        let signature = auth.sign(payload, privateKey);
        assert.equal(signature.signature, expectedSignature);

      });

    it('Should accept the signature', function() {
      
        const signature = "a74b36f7421a52fd7b7857d77082b732a48ba994c8d23a1418650cf4ccdde68f05c8c7e25ec85754300507fea67c7dbe763e3168f0f1858afb1efa1b3ff8907c";
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
    it('Should return SECP256k1 curves', function() {
            expect(curveProvider.curveTable["secp256k1"]()).toEqual(new EC("secp256k1"));
    });
    it('Should return p192 curves', function() {
            expect(curveProvider.curveTable["p192"]()).toEqual(new EC("p192"));
    });
    it('Should return p224 curves', function() {
        expect(curveProvider.curveTable["p224"]()).toEqual(new EC("p224"));
    });
    it('Should return p256 curves', function() {
        expect(curveProvider.curveTable["p256"]()).toEqual(new EC("p256"));
    });
    it('Should return p384 curves', function() {
        expect(curveProvider.curveTable["p384"]()).toEqual(new EC("p384"));
    });
    it('Should return p521 curves', function() {
        expect(curveProvider.curveTable["p521"]()).toEqual(new EC("p521"));
    });
    it('Should return ed25519 curves', function() {
        expect(curveProvider.curveTable["ed25519"]()).toEqual(new EC("ed25519"));
    });
});


describe('Hash', function() {
    it('Should return corresponding digest for KECCAK224', function() {
        var message = "hello";
        expect(hashProvider.hashTable["KECCAK224"](message))
        .toEqual("45524ec454bcc7d4b8f74350c4a4e62809fcb49bc29df62e61b69fa4");
    });
    it('Should return corresponding digest for KECCAK256', function() {
        var message = "hello";
        expect(hashProvider.hashTable["KECCAK256"](message))
        .toEqual("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
    });
    it('Should return corresponding digest for KECCAK512', function() {
        var message = "hello";
        expect(hashProvider.hashTable["KECCAK512"](message))
        .toEqual("52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39d47de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f976");
    });
    it('Should return corresponding digest for SHA3_224', function() {
        var message = "hello";
        expect(hashProvider.hashTable["SHA3_224"](message))
        .toEqual("b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81");
    });
    it('Should return corresponding digest for SHA3_256', function() {
        var message = "hello";
        expect(hashProvider.hashTable["SHA3_256"](message))
        .toEqual("3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392");
    });
    it('Should return corresponding digest for SHA3_384', function() {
        var message = "hello";
        expect(hashProvider.hashTable["SHA3_384"](message))
        .toEqual("720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887");
    });
    it('Should return corresponding digest for SHA3_512', function() {
        var message = "hello";
        expect(hashProvider.hashTable["SHA3_512"](message))
        .toEqual("75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976");
    });
    it('Should return corresponding digest for SHAKE128', function() {
        var message = "hello";
        expect(hashProvider.hashTable["SHAKE128"](message,128))
        .toEqual("8eb4b6a932f280335ee1a279f8c208a3");
    });
    it('Should return corresponding digest for SHAKE256', function() {
        var message = "hello";
        expect(hashProvider.hashTable["SHAKE256"](message,128))
        .toEqual("1234075ae4a1e77316cf2d8000974581");
    });
})