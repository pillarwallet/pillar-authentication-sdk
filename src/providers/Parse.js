exports.createHeader = (username, password) => { 
    return {Authorization: Buffer.from(username+password).toString("base64")};
};