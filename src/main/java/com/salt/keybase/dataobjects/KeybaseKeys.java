package com.salt.keybase.dataobjects;

import java.util.Arrays;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class KeybaseKeys {

    private KeybaseKey[] keys;

    public KeybaseKey[] getKeys() {
        return keys;
    }

    public void setKeys(KeybaseKey[] keys) {
        this.keys = keys;
    }

    @Override
    public String toString() {
        return "KeybaseKeys [keys=" + Arrays.toString(keys) + "]";
    }
    
}