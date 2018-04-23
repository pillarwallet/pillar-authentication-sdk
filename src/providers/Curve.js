var EC = require("elliptic").ec;

exports.curveTable = {
    "secp256k1": () => {
        return new EC("secp256k1");
    },
    "p192": () => {
        return new EC("p192");
    },
    "p224": () => {
        return new EC("p224");
    },
    "p256": () => {
        return new EC("p256");
    },
    "p384": () => {
        return new EC("p384");
    },
    "p521": () => {
        return new EC("p521");
    },
    "ed25519": () => {
        return new EC("ed25519");
    },
    "montgomery": () => {
        return // 
    },
    "short": () => {
        return //
    },
    "edwards": () => {
        return //
    }
}
