package com.salt.keybase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.salt.keybase.dataobjects.Challenge;
import com.salt.keybase.dataobjects.KeybaseKey;
import com.salt.keybase.dataobjects.KeybaseKeys;
import com.salt.keybase.dataobjects.PGPMessageParts;
import com.salt.keybase.dataobjects.UserPrincipal;
import com.salt.keybase.utils.AESUtils;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.io.Streams;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Component
public class KeybaseAuthenticationProvider implements AuthenticationProvider {
	private static final Logger logger = LoggerFactory.getLogger(KeybaseAuthenticationProvider.class);

	@Override
	public Authentication authenticate(Authentication auth) throws AuthenticationException {
		try {
			logger.trace("Authenticating ...");
			if (auth != null) {
				String signedChallenge = ((SignedChallengeAuthenticationToken) auth).getSignedChallenge();
				logger.trace("Signed challenge: " + signedChallenge);
				String verifiedUsername=getVerifiedUsername(signedChallenge);
				if (verifiedUsername!=null) {
					logger.trace("Authentication succesful. Will create a new signed authentication token containing the principal with proper authorities.");
					final List<SimpleGrantedAuthority> authorities = new LinkedList<>();
					authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
					UserPrincipal principal = new UserPrincipal(verifiedUsername, authorities);
					return new SignedChallengeAuthenticationToken(principal, authorities, signedChallenge);
				}
			} 
		} catch (Exception e) {
			String errorMessage="External system authentication failed. Reason: " + e.getMessage();
			logger.error(errorMessage);
			throw new BadCredentialsException(errorMessage);	
		}
		return null;
	}

	@Override
	public boolean supports(Class<?> auth) {
		return auth.equals(SignedChallengeAuthenticationToken.class);
	}

	public String getVerifiedUsername(String signedChallenge) throws Exception {
		if (signedChallenge==null || signedChallenge.length()==0) {
			throw new Exception ("signedChallenge cannot be null or empty.");
		}

		PGPMessageParts pgpMessageParts = readPGPMessageParts(signedChallenge);
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
		PGPPublicKey pgpPublicKey = parsePGPPublicKey(publicKey.getBundle(), keyId);
		
		if (verifySignatures(pgpPublicKey, pgpMessageParts)) {
			logger.trace("Signature verified. Username of public key is: {}", publicKey.getUsername());
			Challenge challenge = new Challenge(new String(pgpMessageParts.getMessage(), StandardCharsets.UTF_8));
			logger.trace("Now validating challenge: {}", challenge.toString());
			byte[] encryptedMessage = Base64.getDecoder()
					.decode(challenge.getEncryptedMessage().getBytes(StandardCharsets.UTF_8));
			byte[] iv = Base64.getDecoder().decode(challenge.getIv().getBytes(StandardCharsets.UTF_8));
			String timeinmillis = AESUtils.getInstance().decrypt(encryptedMessage, iv);
			

			if (!(new Date().after(new Date(Long.valueOf(timeinmillis) + 120000)))) {
				logger.trace("Challenge succesfully validated and message less than two minutes old, so user is verified");
				return publicKey.getUsername();
			} else {
				logger.trace("Signature is valid, but challenge is expired.");
			}
		} else {
			logger.trace("Signature is not valid");
		}

		return null;
	}

	private static PGPMessageParts readPGPMessageParts(String signedChallenge) throws IOException, PGPException {

		InputStream input = PGPUtil
				.getDecoderStream(new ByteArrayInputStream(signedChallenge.getBytes(StandardCharsets.UTF_8)));
		PGPObjectFactory objectFactory = new PGPObjectFactory(input, new BcKeyFingerprintCalculator());

		Object message = objectFactory.nextObject();
		ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

		PGPOnePassSignatureList onePassSignatureList = null;
		PGPSignatureList signatureList = null;
		PGPCompressedData compressedData;

		if (message == null) {
			throw new PGPException("Unknown message type and not recognized as valid PGP message.");
		}

		while (message != null) {
			if (message instanceof PGPCompressedData) {
				compressedData = (PGPCompressedData) message;
				objectFactory = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
				message = objectFactory.nextObject();
			}

			if (message instanceof PGPLiteralData) {
				// have to read it and keep it somewhere.
				Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
			} else if (message instanceof PGPOnePassSignatureList) {
				onePassSignatureList = (PGPOnePassSignatureList) message;
			} else if (message instanceof PGPSignatureList) {
				signatureList = (PGPSignatureList) message;
			} else {
				throw new PGPException("Unknown message type and not recognized as valid PGP message.");
			}
			message = objectFactory.nextObject();
		}
		actualOutput.close();
		byte[] output = actualOutput.toByteArray();
		return new PGPMessageParts(onePassSignatureList, signatureList, output);
	}

	private static PGPPublicKey parsePGPPublicKey(String publicKey, long keyId) throws IOException, PGPException {
		InputStream input = PGPUtil
				.getDecoderStream(new ByteArrayInputStream(publicKey.getBytes(StandardCharsets.UTF_8)));
		KeyFingerPrintCalculator fingerCalc = new BcKeyFingerprintCalculator();
		PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(input, fingerCalc);
		return pgpRings.getPublicKey(keyId);
	}

	private static boolean verifySignatures(PGPPublicKey publicKey, PGPMessageParts pgpMessageParts)
			throws PGPException {
		for (int i = 0; i < pgpMessageParts.getOnePassSignatureList().size(); i++) {
			PGPOnePassSignature ops = pgpMessageParts.getOnePassSignatureList().get(i);
			PGPSignature sig = pgpMessageParts.getSignatureList().get(i);
			ops.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
			ops.update(pgpMessageParts.getMessage());

			if (!ops.verify(sig)) {
				throw new PGPException("Signature verification failed.");
			}
		}
		return true;
	}
}
