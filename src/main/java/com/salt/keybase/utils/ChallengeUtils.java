package com.salt.keybase.utils;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.salt.keybase.dataobjects.Challenge;
import com.salt.keybase.dataobjects.KeybaseKey;
import com.salt.keybase.dataobjects.KeybaseKeys;
import com.salt.keybase.dataobjects.PGPMessageParts;
import com.salt.keybase.dataobjects.SignedResponse;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ChallengeUtils {
    private static final Logger logger = LoggerFactory.getLogger(ChallengeUtils.class.getName());

    // Hide constructor on purpose. Class methods are supposed to be accessed
    // statically.
    private ChallengeUtils() {
    }

    public static Challenge generateChallenge() throws Exception {
        Challenge challenge = new Challenge();
        challenge.setTimeinmillis(Long.toString(new Date().getTime()));
        byte[] iv = AESUtils.getInstance().getRandomNonce();
        String encryptedTimeinmillis = Base64.getEncoder().encodeToString(
                AESUtils.getInstance().encrypt(challenge.getTimeinmillis().getBytes(StandardCharsets.UTF_8), iv));
        String encodedIV = Base64.getEncoder().encodeToString(iv);
        challenge.setEncryptedChallenge(encryptedTimeinmillis);
        challenge.setEncodedIV(encodedIV);
        return challenge;
    }

    public static SignedResponse verifySignedResponse(SignedResponse signedResponse) throws Exception {
        if (signedResponse==null ) {
			throw new Exception ("signedResponse cannot be null");
        }

        String signedResponseCiphertext=signedResponse.getSignedResponseCiphertext();

        if (signedResponseCiphertext==null ) {
			throw new Exception ("signedResponseCiphertext cannot be null");
        }

        
        PGPMessageParts pgpMessageParts = PGPUtils.readPGPMessageParts(signedResponseCiphertext);
		long keyId = pgpMessageParts.getOnePassSignatureList().get(0).getKeyID();
		String keyIdHex = Long.toHexString(keyId);
		logger.trace("keyIdHex: {}", keyIdHex);

        HttpClient client = HttpClient.newBuilder().version(Version.HTTP_2).build();

		HttpRequest request = HttpRequest
				.newBuilder(URI.create("https://keybase.io/_/api/1.0/key/fetch.json?pgp_key_ids=" + keyIdHex))
				.header("Content-Type", "application/json").GET().build();

		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

		KeybaseKeys keys = new ObjectMapper().readValue(response.body(), KeybaseKeys.class);
		KeybaseKey publicKey = keys.getKeys()[0];
		PGPPublicKey pgpPublicKey = PGPUtils.parsePGPPublicKey(publicKey.getBundle(), keyId);
		
		if (PGPUtils.verifySignatures(pgpPublicKey, pgpMessageParts)) {
            logger.trace("Signature verified. Username of public key is: {}", publicKey.getUsername());
            signedResponse.setPublicKeyOfSigner(publicKey);
            String encryptedChallenge=new String(pgpMessageParts.getMessage(), StandardCharsets.UTF_8);

            Challenge originalChallenge=signedResponse.getOriginalChallenge();
            originalChallenge.setEncryptedChallenge(encryptedChallenge);
            
            originalChallenge=verifyChallenge(originalChallenge);
            signedResponse.setOriginalChallenge(originalChallenge);
		} else {
			logger.trace("Signature is not valid");
		}

        return signedResponse;
    }

    private static Challenge verifyChallenge(Challenge originalChallenge) throws NoSuchAlgorithmException, Exception {

        logger.trace("Now validating encryptedChallenge");
        byte[] encryptedChallenge = Base64.getDecoder()
                .decode(originalChallenge.getEncryptedChallenge().getBytes(StandardCharsets.UTF_8));
        byte[] iv = Base64.getDecoder().decode(originalChallenge.getEncodedIV().getBytes(StandardCharsets.UTF_8));
        String timeinmillis = AESUtils.getInstance().decrypt(encryptedChallenge, iv);
        
        if (!(new Date().after(new Date(Long.valueOf(timeinmillis) + 120000)))) {
            logger.trace("Challenge succesfully validated and message less than two minutes old, so user is verified");
            originalChallenge.setTimeinmillis(timeinmillis);
        } else {
            logger.trace("Signature is valid, but challenge is expired.");
            throw new Exception ("Signature is valid, but challenge is expired.");
        }        

        return originalChallenge;
    }
}