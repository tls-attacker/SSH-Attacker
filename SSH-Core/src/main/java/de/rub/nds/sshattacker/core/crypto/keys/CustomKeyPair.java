/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import jakarta.xml.bind.annotation.*;

import java.io.Serializable;

/** This serializable class represents a key pair consisting of a public and private key. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomKeyPair<PRIVATE extends CustomPrivateKey, PUBLIC extends CustomPublicKey>
        implements Serializable {

    @XmlElements({
        @XmlElement(name = "dhPrivateKey", type = CustomDhPrivateKey.class),
        @XmlElement(name = "dsaPrivateKey", type = CustomDsaPrivateKey.class),
        @XmlElement(name = "ecPrivateKey", type = CustomEcPrivateKey.class),
        @XmlElement(name = "rsaPrivateKey", type = CustomRsaPrivateKey.class),
        @XmlElement(name = "xCurvePrivateKey", type = XCurveEcPrivateKey.class)
    })
    private PRIVATE privateKey;

    @XmlElements({
        @XmlElement(name = "dhPublicKey", type = CustomDhPublicKey.class),
        @XmlElement(name = "dsaPublicKey", type = CustomDsaPublicKey.class),
        @XmlElement(name = "ecPublicKey", type = CustomEcPublicKey.class),
        @XmlElement(name = "rsaPublicKey", type = CustomRsaPublicKey.class),
        @XmlElement(name = "xCurvePublicKey", type = XCurveEcPublicKey.class)
    })
    private PUBLIC publicKey;

    public CustomKeyPair(PRIVATE privateKey, PUBLIC publicKey) {
        super();
        if (privateKey == null || publicKey == null) {
            throw new IllegalArgumentException(
                    "Unable to construct key pair with its public key being null");
        }
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public PRIVATE getPrivateKey() {
        return privateKey;
    }

    public PUBLIC getPublicKey() {
        return publicKey;
    }
}
