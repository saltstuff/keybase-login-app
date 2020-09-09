package com.salt.keybase.dataobjects;

public class SignedResponse {
    private String signedResponseCiphertext;
    private Challenge originalChallenge;
    private KeybaseKey publicKeyOfSigner;

    
    
    public Challenge getOriginalChallenge() {
        return originalChallenge;
    }

    public void setOriginalChallenge(Challenge originalChallenge) {
        this.originalChallenge = originalChallenge;
    }

    public KeybaseKey getPublicKeyOfSigner() {
        return publicKeyOfSigner;
    }

    public void setPublicKeyOfSigner(KeybaseKey publicKeyOfSigner) {
        this.publicKeyOfSigner = publicKeyOfSigner;
    }

    public String getSignedResponseCiphertext() {
        return signedResponseCiphertext;
    }

    public void setSignedResponseCiphertext(String signedResponseCiphertext) {
        this.signedResponseCiphertext = signedResponseCiphertext;
    }
}
