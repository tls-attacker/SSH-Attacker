/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class HostKey extends ModifiableVariableHolder {

    private PublicKeyAlgorithm publicKeyAlgorithm;
    private CustomKeyPair<PrivateKey, PublicKey> keyPair;

    public HostKey(
            PublicKeyAlgorithm publicKeyAlgorithm, CustomKeyPair<PrivateKey, PublicKey> keyPair) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.keyPair = keyPair;
    }

    public HostKey(PublicKeyAlgorithm publicKeyAlgorithm, PublicKey publicKey) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.keyPair = new CustomKeyPair<>(null, publicKey);
    }

    public PublicKeyAlgorithm getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public void setPublicKeyAlgorithm(PublicKeyAlgorithm publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public CustomKeyPair<PrivateKey, PublicKey> getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(CustomKeyPair<PrivateKey, PublicKey> keyPair) {
        this.keyPair = keyPair;
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        holders.add(keyPair);
        return holders;
    }
}
