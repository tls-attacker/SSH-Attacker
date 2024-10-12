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
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertXCurvePublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class SignatureFactory {

    public static SigningSignature getSigningSignature(
            PublicKeyAlgorithm algorithm, SshPublicKey<?, ?> keyPair) throws CryptoException {
        if (algorithm.getKeyFormat() != keyPair.getPublicKeyFormat()) {
            throw new CryptoException(
                    "The key format of the provided SshPublicKey instance does not match the format specified by the algorithm");
        }
        if (keyPair.getPrivateKey().isEmpty()) {
            throw new CryptoException(
                    "The provided SshPublicKey instance does not contain a private key to support signing operations");
        }
        return getSigningSignature(algorithm, keyPair.getPrivateKey().get());
    }

    public static SigningSignature getSigningSignature(
            PublicKeyAlgorithm algorithm,
            CustomKeyPair<? extends PrivateKey, ? extends PublicKey> keyPair) {
        return getSigningSignature(algorithm, keyPair.getPrivateKey());
    }

    public static SigningSignature getSigningSignature(
            PublicKeyAlgorithm algorithm, PrivateKey privateKey) {
        if (algorithm.getSignatureEncoding() == SignatureEncoding.SSH_DSS) {
            return new UnpackedDsaJavaSignature(algorithm, privateKey);
        } else if (algorithm.getName().startsWith("ecdsa-sha2-")) {
            return new UnpackedEcdsaJavaSignature(algorithm, privateKey);
        } else if (algorithm.getJavaName() != null) {
            // Keys for Curve25519 and Curve448 require conversion to a JCA-compatible key
            if (privateKey instanceof XCurveEcPrivateKey) {
                privateKey = ((XCurveEcPrivateKey) privateKey).toEdDsaKey();
            }
            return new JavaSignature(algorithm, privateKey);
        }
        throw new NotImplementedException(
                "Public key algorithm '" + algorithm + "' is not yet supported.");
    }

    public static VerifyingSignature getVerifyingSignature(
            PublicKeyAlgorithm algorithm, SshPublicKey<?, ?> publicKey) throws CryptoException {
        if (algorithm.getKeyFormat() != publicKey.getPublicKeyFormat()) {
            throw new CryptoException(
                    "The key format of the provided SshPublicKey instance does not match the format specified by the algorithm");
        }
        return getVerifyingSignature(algorithm, publicKey.getPublicKey());
    }

    public static VerifyingSignature getVerifyingSignature(
            PublicKeyAlgorithm algorithm,
            CustomKeyPair<? extends PrivateKey, ? extends PublicKey> keyPair) {
        return getVerifyingSignature(algorithm, keyPair.getPublicKey());
    }

    public static VerifyingSignature getVerifyingSignature(
            PublicKeyAlgorithm algorithm, PublicKey publicKey) {
        if (algorithm.getSignatureEncoding() == SignatureEncoding.SSH_DSS) {
            return new UnpackedDsaJavaSignature(algorithm, publicKey);
        } else if (algorithm.getName().startsWith("ecdsa-sha2-")) {
            return new UnpackedEcdsaJavaSignature(algorithm, publicKey);
        } else if (algorithm.getName().startsWith("ssh-rsa-cert-")) {
            return new JavaSignature(algorithm, publicKey);
        } else if (algorithm.getName().startsWith("ssh-dss-cert-")) {
            return new JavaSignature(algorithm, publicKey);
        } else if (algorithm.getJavaName() != null) {
            // Keys for Curve25519 and Curve448 require conversion to a JCA-compatible key
            if (publicKey instanceof XCurveEcPublicKey) {
                publicKey = ((XCurveEcPublicKey) publicKey).toEdDsaKey();
            }
            if (publicKey instanceof CustomCertXCurvePublicKey) {
                publicKey = ((CustomCertXCurvePublicKey) publicKey).toEdDsaKey();
            }
            return new JavaSignature(algorithm, publicKey);
        }
        throw new NotImplementedException(
                "Public key algorithm '" + algorithm + "' is not yet supported.");
    }

    public static VerifyingSignature getVerifyingSignature(
            PublicKeyAlgorithm algorithm, byte[] encodedPublicKeyBytes) throws CryptoException {
        SshPublicKey<?, ?> publicKey =
                PublicKeyHelper.parse(algorithm.getKeyFormat(), encodedPublicKeyBytes);
        return getVerifyingSignature(algorithm, publicKey);
    }

    private SignatureFactory() {
        super();
    }
}
