package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;

import java.security.PrivateKey;
import java.security.PublicKey;

public class SignatureFactory {

    public static JavaSignature getSigningSignature(
            SignatureAlgorithm signatureAlgorithm,
            PrivateKey privateKey
    ) {
        return new JavaSignature(signatureAlgorithm, privateKey);
    }

    public static JavaSignature getSigningSignature(
            SignatureAlgorithm signatureAlgorithm,
            CustomKeyPair keyPair
    ) {
        return new JavaSignature(signatureAlgorithm, keyPair.getPrivate());
    }


    public static JavaSignature getVerificationSignature(
            SignatureAlgorithm signatureAlgorithm,
            PublicKey publicKey
    ) {
        return new JavaSignature(signatureAlgorithm, publicKey);
    }

    public static JavaSignature getVerificationSignature(
            SignatureAlgorithm signatureAlgorithm,
            CustomKeyPair keyPair
    ) {
        return new JavaSignature(signatureAlgorithm, keyPair.getPublic());
    }

    private SignatureFactory(){}
}
