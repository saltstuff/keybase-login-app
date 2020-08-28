package com.salt.keybase.dataobjects;

public class Challenge {
    private String encryptedMessage;
    private String iv;

    public Challenge(String concatenatedMessage) {
        if (concatenatedMessage!=null) {
            String[] challengeElements=concatenatedMessage.split(",");
            if (challengeElements.length>1) {
                this.encryptedMessage = challengeElements[0];
                this.iv = challengeElements[1];
            }
        }
    }

    public Challenge(String encryptedMessage, String iv) {
        this.encryptedMessage = encryptedMessage;
        this.iv = iv;
    }  

    public String getEncryptedMessage() {
        return encryptedMessage;
    }

    public String getIv() {
        return iv;
    }

    @Override
    public String toString() {
        return encryptedMessage+","+iv;
    }

    
}