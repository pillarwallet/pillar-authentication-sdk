var assert = require('assert');
var auth = require('../');

    
describe('Signature', function() {
    it('Should return a specific signature', function() {

        const privateKey = "1234567890123456789012345678901234567890123456789012345678901234";
        const payload = {a: "1"};
        const expectedSignature = "a74b36f7421a52fd7b7857d77082b732a48ba994c8d23a1418650cf4ccdde68f5c8c7e25ec85754300507fea67c7dbe763e3168f0f1858afb1efa1b3ff8907c";

        let signature = auth.sign(payload, privateKey);
        assert.equal(signature, expectedSignature);

      });

    it('Should verify a signature', function() {
      
    const signature = "a74b36f7421a52fd7b7857d77082b732a48ba994c8d23a1418650cf4ccdde68f5c8c7e25ec85754300507fea67c7dbe763e3168f0f1858afb1efa1b3ff8907c";
    const signedPayload = {
        a: "1",
        signature
    };
    const publicKey = "02e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e";
    assert.ok(auth.verify(signedPayload, publicKey));

    });

    it('Should reject a signature', function() {
        
        const signature = "174b36f7421a52fd7b7857d77082b732a48ba994c8d23a1418650cf4ccdde68f5c8c7e25ec85754300507fea67c7dbe763e3168f0f1858afb1efa1b3ff8907c";
        const signedPayload = {
            a: "1",
            signature: signature
        };
        const publicKey = "02e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e";
        assert.ok(!auth.verify(signedPayload, publicKey));
    });
});