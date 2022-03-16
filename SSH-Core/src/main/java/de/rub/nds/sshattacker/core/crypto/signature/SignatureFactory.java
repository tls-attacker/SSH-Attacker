/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.constants.SignatureEncoding;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.HostKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SignatureFactory {

    public static SigningSignature getSigningSignature(HostKey hostKey)
            throws NoSuchAlgorithmException {
        return getSigningSignature(hostKey.getPublicKeyAlgorithm(), hostKey.getPrivateKey());
    }

    public static SigningSignature getSigningSignature(
            PublicKeyAlgorithm algorithm,
            CustomKeyPair<? extends PrivateKey, ? extends PublicKey> keyPair)
            throws NoSuchAlgorithmException {
        return getSigningSignature(algorithm, keyPair.getPrivate());
    }

    public static SigningSignature getSigningSignature(
            PublicKeyAlgorithm algorithm, PrivateKey privateKey) throws NoSuchAlgorithmException {
        if (algorithm.getSignatureEncoding() == SignatureEncoding.SSH_DSS) {
            return new UnpackedDsaJavaSignature(algorithm, privateKey);
        } else if (algorithm.getJavaName() != null) {
            return new JavaSignature(algorithm, privateKey);
        }
        throw new NoSuchAlgorithmException(
                "Public key algorithm '" + algorithm + "' is not supported.");
    }

    public static VerifyingSignature getVerifyingSignature(HostKey hostKey)
            throws NoSuchAlgorithmException {
        return getVerifyingSignature(hostKey.getPublicKeyAlgorithm(), hostKey.getPublicKey());
    }

    public static VerifyingSignature getVerifyingSignature(
            PublicKeyAlgorithm algorithm,
            CustomKeyPair<? extends PrivateKey, ? extends PublicKey> keyPair)
            throws NoSuchAlgorithmException {
        return getVerifyingSignature(algorithm, keyPair.getPublic());
    }

    public static VerifyingSignature getVerifyingSignature(
            PublicKeyAlgorithm algorithm, PublicKey publicKey) throws NoSuchAlgorithmException {
        if (algorithm.getSignatureEncoding() == SignatureEncoding.SSH_DSS) {
            return new UnpackedDsaJavaSignature(algorithm, publicKey);
        } else if (algorithm.getJavaName() != null) {
            return new JavaSignature(algorithm, publicKey);
        }
        throw new NoSuchAlgorithmException(
                "Public key algorithm '" + algorithm + "' is not supported.");
    }

    public static VerifyingSignature getVerifyingSignature(
            PublicKeyAlgorithm publicKeyAlgorithm, byte[] encodedPublicKeyBytes)
            throws NoSuchAlgorithmException {
        PublicKey publicKey =
                PublicKeyHelper.parse(publicKeyAlgorithm.getKeyFormat(), encodedPublicKeyBytes);
        return getVerifyingSignature(publicKeyAlgorithm, publicKey);
    }

    private SignatureFactory() {}
}
