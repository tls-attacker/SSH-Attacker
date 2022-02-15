/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import java.security.PrivateKey;
import java.security.PublicKey;

public class CustomKeyPair<PRIVATE extends PrivateKey, PUBLIC extends PublicKey> {

    private final PRIVATE privateKey;
    private final PUBLIC publicKey;

    public CustomKeyPair(PRIVATE privateKey, PUBLIC publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public PRIVATE getPrivate() {
        return privateKey;
    }

    public PUBLIC getPublic() {
        return publicKey;
    }
}
