package com.salt.keybase.dataobjects;

public class Challenge {
    private String timeinmillis;
    private String encryptedChallenge;
    private String encodedIV;

    public Challenge() {        
    }

    public String getTimeinmillis() {
        return timeinmillis;
    }


    public void setTimeinmillis(String timeinmillis) {
        this.timeinmillis = timeinmillis;
    }


    public String getEncryptedChallenge() {
        return encryptedChallenge;
    }

    public void setEncryptedChallenge(String encryptedChallenge) {
        this.encryptedChallenge = encryptedChallenge;
    }

    public String getEncodedIV() {
        return encodedIV;
    }

    public void setEncodedIV(String encodedIV) {
        this.encodedIV = encodedIV;
    }
}