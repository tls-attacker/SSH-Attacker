/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.security.PublicKey;

/**
 * An abstract base class for all custom public key classes implemented by SSH-Attacker. This class
 * overrides the getFormat() and getEncoded() methods of the PrivateKey interface to return null (no
 * encoding support).
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class CustomPublicKey implements PublicKey {

    protected CustomPublicKey() {
        super();
    }

    protected CustomPublicKey(CustomPublicKey other) {
        super();
    }

    public abstract CustomPublicKey createCopy();

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    public abstract byte[] serialize();
}
