/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.sshattacker.core.exceptions.CryptoException;

import java.security.*;

public class JavaSignature implements VerificationSignature, SigningSignature {

    private final SignatureAlgorithm algorithm;
    private final Key key;
    private Signature signature;


    public JavaSignature(SignatureAlgorithm algorithm, Key key){
        this.algorithm = algorithm;
        this.key = key;
    }

    @Override
    public boolean verify(byte[] data, byte[] signatureBytes) throws CryptoException {
        try {
            if (signature == null) {
                signature = Signature.getInstance(algorithm.getJavaName());
                if (key instanceof PublicKey) {
                    signature.initVerify((PublicKey) key);
                } else {
                    throw new CryptoException("Tried to initialize Signature for verification, " +
                            "but provided key is not a public key");
                }
            }
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("Encountered exception during verification: " + e.getMessage());
        }

    }

    @Override
    public byte[] sign(byte[] data) throws CryptoException {
        try {
            if (signature == null) {
                signature = Signature.getInstance(algorithm.getJavaName());
                if (key instanceof PrivateKey) {
                    signature.initSign((PrivateKey) key);
                } else {
                    throw new CryptoException("Tried to initialize Signature for signing, " +
                            "but provided key is not a private key");
                }
            }
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new CryptoException("Encountered exception during signing.", e);
        }
    }

    @Override
    public SignatureAlgorithm getAlgorithm() {
        return algorithm;
    }
}
