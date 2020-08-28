package com.salt.keybase.dataobjects;

import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPSignatureList;

/**
 * Holds decrypted content and associated signatures to verify
 */
public class PGPMessageParts {
    private final PGPOnePassSignatureList onePassSignatureList;
    private final PGPSignatureList signatureList;
    private final byte[] message;

    public PGPMessageParts(final PGPOnePassSignatureList onePassSignatureList, final PGPSignatureList signatureList, byte[] message) {

        this.onePassSignatureList = onePassSignatureList;
        this.signatureList = signatureList;
        this.message=message;
        
    }

    public PGPOnePassSignatureList getOnePassSignatureList() {
        return onePassSignatureList;
    }

    public PGPSignatureList getSignatureList() {
        return signatureList;
    }

    public byte[] getMessage() {
        return message;
    }
}