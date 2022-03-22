/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

/**
 * This class represents a public key with its corresponding public key algorithm as used throughout
 * the SSH protocol. A corresponding private key may be present in case of a local key.
 */
public class SshPublicKey<PUBLIC extends PublicKey, PRIVATE extends PrivateKey>
        extends ModifiableVariableHolder {

    private final PublicKeyFormat publicKeyAlgorithm;
    private final PUBLIC publicKey;
    private final PRIVATE privateKey;

    public SshPublicKey(PublicKeyFormat publicKeyFormat, CustomKeyPair<PRIVATE, PUBLIC> keyPair) {
        this(publicKeyFormat, keyPair.getPublic(), keyPair.getPrivate());
    }

    public SshPublicKey(PublicKeyFormat publicKeyAlgorithm, PUBLIC publicKey) {
        this(publicKeyAlgorithm, publicKey, null);
    }

    public SshPublicKey(PublicKeyFormat publicKeyAlgorithm, PUBLIC publicKey, PRIVATE privateKey) {
        if (publicKeyAlgorithm == null || publicKey == null) {
            throw new IllegalArgumentException(
                    "Unable to construct SshPublicKey with public key algorithm or public key being null");
        }
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKeyFormat getPublicKeyFormat() {
        return publicKeyAlgorithm;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public Optional<PrivateKey> getPrivateKey() {
        return Optional.ofNullable(privateKey);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (publicKey instanceof ModifiableVariableHolder) {
            holders.add((ModifiableVariableHolder) publicKey);
        }
        if (privateKey instanceof ModifiableVariableHolder) {
            holders.add((ModifiableVariableHolder) privateKey);
        }
        return holders;
    }
}
