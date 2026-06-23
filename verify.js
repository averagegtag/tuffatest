const crypto = require("crypto");

// Verify every cert in the chain is signed by the next one
async function verifyChain(certChainB64) {
    try {
        const certs = certChainB64.map(b64 => Buffer.from(b64, "base64"));

        for (let i = 0; i < certs.length - 1; i++) {
            const child  = new crypto.X509Certificate(certs[i]);
            const parent = new crypto.X509Certificate(certs[i + 1]);

            if (!child.verify(parent.publicKey)) {
                return false;
            }
        }

        // Optionally: verify root against Google's known attestation root CA
        // const root = new crypto.X509Certificate(certs[certs.length - 1]);
        // if (root.subject !== GOOGLE_ATTESTATION_ROOT_SUBJECT) return false;

        return true;
    } catch (e) {
        console.error("[verifyChain]", e.message);
        return false;
    }
}

// Verify the nonce was signed by the private key matching the leaf cert
async function verifyNonceSig(nonceB64, sigB64, leafCertB64) {
    try {
        const cert = new crypto.X509Certificate(Buffer.from(leafCertB64, "base64"));
        const verify = crypto.createVerify("SHA256withECDSA");
        verify.update(Buffer.from(nonceB64, "base64"));
        return verify.verify(cert.publicKey, Buffer.from(sigB64, "base64"));
    } catch (e) {
        console.error("[verifyNonceSig]", e.message);
        return false;
    }
}

module.exports = { verifyChain, verifyNonceSig };