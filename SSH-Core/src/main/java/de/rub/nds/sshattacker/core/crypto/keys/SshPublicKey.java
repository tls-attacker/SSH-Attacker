/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import jakarta.xml.bind.annotation.*;
import java.io.Serializable;
import java.util.Optional;

/**
 * This class represents a public key with its corresponding public key algorithm as used throughout
 * the SSH protocol. A corresponding private key may be present in case of a local key.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SshPublicKey<PUBLIC extends CustomPublicKey, PRIVATE extends CustomPrivateKey>
        implements Serializable {

    private PublicKeyFormat publicKeyFormat;

    @XmlElements({
        @XmlElement(name = "dhPublicKey", type = CustomDhPublicKey.class),
        @XmlElement(name = "dsaPublicKey", type = CustomDsaPublicKey.class),
        @XmlElement(name = "ecPublicKey", type = CustomEcPublicKey.class),
        @XmlElement(name = "rsaPublicKey", type = CustomRsaPublicKey.class),
        @XmlElement(name = "xCurvePublicKey", type = XCurveEcPublicKey.class)
    })
    private PUBLIC publicKey;

    @XmlElements({
        @XmlElement(name = "dhPrivateKey", type = CustomDhPrivateKey.class),
        @XmlElement(name = "dsaPrivateKey", type = CustomDsaPrivateKey.class),
        @XmlElement(name = "ecPrivateKey", type = CustomEcPrivateKey.class),
        @XmlElement(name = "rsaPrivateKey", type = CustomRsaPrivateKey.class),
        @XmlElement(name = "xCurvePrivateKey", type = XCurveEcPrivateKey.class)
    })
    private PRIVATE privateKey;

    protected SshPublicKey() {
        super();
    }

    public SshPublicKey(PublicKeyFormat publicKeyFormat, CustomKeyPair<PRIVATE, PUBLIC> keyPair) {
        this(publicKeyFormat, keyPair.getPublicKey(), keyPair.getPrivateKey());
    }

    public SshPublicKey(PublicKeyFormat publicKeyFormat, PUBLIC publicKey) {
        this(publicKeyFormat, publicKey, null);
    }

    public SshPublicKey(PublicKeyFormat publicKeyFormat, PUBLIC publicKey, PRIVATE privateKey) {
        super();
        if (publicKeyFormat == null || publicKey == null) {
            throw new IllegalArgumentException(
                    "Unable to construct SshPublicKey with public key algorithm or public key being null");
        }
        this.publicKeyFormat = publicKeyFormat;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKeyFormat getPublicKeyFormat() {
        return publicKeyFormat;
    }

    public PUBLIC getPublicKey() {
        return publicKey;
    }

    public Optional<PRIVATE> getPrivateKey() {
        return Optional.ofNullable(privateKey);
    }

    public String toString() {
        return String.format(
                "SshPublicKey[%s,%s]",
                publicKeyFormat.toString(), getPrivateKey().map(key -> "private").orElse("public"));
    }
}
