package com.salt.keybase.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import com.salt.keybase.dataobjects.PGPMessageParts;

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

public class PGPUtils {
   
    // Hide constructor on purpose. Class methods are supposed to be accessed statically.
    private PGPUtils() {
    }
     
    public static PGPMessageParts readPGPMessageParts(String signedChallenge) throws IOException, PGPException {

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

	public static PGPPublicKey parsePGPPublicKey(String publicKey, long keyId) throws IOException, PGPException {
		InputStream input = PGPUtil
				.getDecoderStream(new ByteArrayInputStream(publicKey.getBytes(StandardCharsets.UTF_8)));
		KeyFingerPrintCalculator fingerCalc = new BcKeyFingerprintCalculator();
		PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(input, fingerCalc);
		return pgpRings.getPublicKey(keyId);
	}

	public static boolean verifySignatures(PGPPublicKey publicKey, PGPMessageParts pgpMessageParts)
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
