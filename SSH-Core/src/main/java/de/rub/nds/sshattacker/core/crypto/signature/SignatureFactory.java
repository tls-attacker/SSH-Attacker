/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.sshattacker.core.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.util.HostKeyParserFactory;

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
            CustomKeyPair<? extends PrivateKey, ? extends PublicKey> keyPair
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
            CustomKeyPair<? extends PrivateKey, ? extends PublicKey> keyPair
    ) {
        return new JavaSignature(signatureAlgorithm, keyPair.getPublic());
    }

    public static JavaSignature getVerificationSignatureForHostKey(
            SignatureAlgorithm signatureAlgorithm,
            byte[] hostKeyBytes,
            PublicKeyAuthenticationAlgorithm algorithm
    ) {
        PublicKey publicKey = HostKeyParserFactory.getParserForHostKeyAlgorithm(algorithm, hostKeyBytes).parse();
        return getVerificationSignature(signatureAlgorithm, publicKey);
    }

    private SignatureFactory(){}
}
