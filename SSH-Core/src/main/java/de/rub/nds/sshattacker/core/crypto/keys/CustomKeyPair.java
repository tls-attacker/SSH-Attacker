/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/** This class represents a key pair consisting of a public and private key. */
public class CustomKeyPair<PRIVATE extends PrivateKey, PUBLIC extends PublicKey>
        extends ModifiableVariableHolder {

    private final PRIVATE privateKey;
    private final PUBLIC publicKey;

    public CustomKeyPair(PRIVATE privateKey, PUBLIC publicKey) {
        if (privateKey == null || publicKey == null) {
            throw new IllegalArgumentException(
                    "Unable to construct key pair with its public key being null");
        }
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public PRIVATE getPrivate() {
        return privateKey;
    }

    public PUBLIC getPublic() {
        return publicKey;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (privateKey instanceof ModifiableVariableHolder) {
            holders.add((ModifiableVariableHolder) privateKey);
        }
        if (publicKey instanceof ModifiableVariableHolder) {
            holders.add((ModifiableVariableHolder) publicKey);
        }
        return holders;
    }
}
