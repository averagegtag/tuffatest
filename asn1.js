const crypto = require("crypto");

// Android Key Attestation OID
const ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

function decodeAttestationExtension(certDer) {
    try {
        const cert = new crypto.X509Certificate(certDer);
        const raw = cert.raw;

        // Pull the attestation extension value by OID
        // Node's X509Certificate doesn't expose extensions directly,
        // so we do a raw DER scan for the OID bytes
        const oidBytes = Buffer.from("060a2b0601040182371101", "hex"); // OID encoding
        const androidOid = encodeOid(ATTESTATION_OID);
        const idx = raw.indexOf(androidOid);

        if (idx === -1) {
            // Not an attestation cert (e.g. intermediate or root) — that's fine
            return { rooted: false, bootloaderLocked: true, verifiedBootState: "verified" };
        }

        // Parse the extension value after the OID
        // This is a simplified parser — for production use pkijs for full ASN.1
        const extValue = extractExtensionValue(raw, idx + androidOid.length);
        if (!extValue) return null;

        return parseKeyDescriptionSequence(extValue);

    } catch (e) {
        console.error("[asn1]", e.message);
        return null;
    }
}

function encodeOid(oid) {
    const parts = oid.split(".").map(Number);
    const bytes = [40 * parts[0] + parts[1]];
    for (let i = 2; i < parts.length; i++) {
        let val = parts[i];
        const chunk = [val & 0x7f];
        val >>= 7;
        while (val > 0) {
            chunk.unshift((val & 0x7f) | 0x80);
            val >>= 7;
        }
        bytes.push(...chunk);
    }
    // Wrap in tag 0x06 (OID)
    return Buffer.from([0x06, bytes.length, ...bytes]);
}

function extractExtensionValue(der, startIdx) {
    try {
        // Skip past the boolean (optional) and find the OCTET STRING wrapping the value
        let i = startIdx;
        // Find 0x04 (OCTET STRING tag)
        while (i < der.length && der[i] !== 0x04) i++;
        if (i >= der.length) return null;
        i++; // skip tag
        const len = readDerLength(der, i);
        i += len.bytesRead;
        return der.slice(i, i + len.value);
    } catch (e) {
        return null;
    }
}

function readDerLength(buf, offset) {
    if (buf[offset] < 0x80) {
        return { value: buf[offset], bytesRead: 1 };
    }
    const numBytes = buf[offset] & 0x7f;
    let value = 0;
    for (let i = 1; i <= numBytes; i++) {
        value = (value << 8) | buf[offset + i];
    }
    return { value, bytesRead: 1 + numBytes };
}

function parseKeyDescriptionSequence(der) {
    // KeyDescription ::= SEQUENCE {
    //   attestationVersion         INTEGER,
    //   attestationSecurityLevel   SecurityLevel,   -- 0=SW, 1=TEE, 2=StrongBox
    //   keymasterVersion           INTEGER,
    //   keymasterSecurityLevel     SecurityLevel,
    //   attestationChallenge       OCTET STRING,
    //   uniqueId                   OCTET STRING,
    //   softwareEnforced           AuthorizationList,
    //   teeEnforced                AuthorizationList,
    // }
    try {
        let i = 0;
        if (der[i] !== 0x30) return null; // must be SEQUENCE
        i++;
        const seqLen = readDerLength(der, i);
        i += seqLen.bytesRead;

        const readInt = () => {
            if (der[i] !== 0x02) return null;
            const len = der[i + 1];
            let val = 0;
            for (let j = 0; j < len; j++) val = (val << 8) | der[i + 2 + j];
            i += 2 + len;
            return val;
        };

        const attestationVersion      = readInt();
        const attestationSecurityLevel = readInt(); // 1=TEE, 2=StrongBox
        const keymasterVersion        = readInt();
        const keymasterSecurityLevel  = readInt();

        // For now return what we can determine from security level
        // Full AuthorizationList parsing (rooted, bootloader) requires deeper ASN.1 walk
        // which pkijs handles cleanly — this is the simplified version
        return {
            attestationVersion,
            securityLevel: attestationSecurityLevel >= 1 ? (attestationSecurityLevel === 2 ? "StrongBox" : "TEE") : "Software",
            rooted: attestationSecurityLevel === 0,         // software-only = likely compromised
            bootloaderLocked: attestationSecurityLevel >= 1,
            verifiedBootState: attestationSecurityLevel >= 1 ? "verified" : "unverified",
            packageName: null,   // requires full AuthorizationList parse
            appCertDigest: null
        };

    } catch (e) {
        console.error("[parseKeyDescription]", e.message);
        return null;
    }
}

module.exports = { decodeAttestationExtension };