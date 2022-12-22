/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.sshattacker.core.constants.OpenQuantumSafeKemNames;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomPQKemPrivateKey extends CustomPrivateKey {
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] privateKey;

    private OpenQuantumSafeKemNames kemName;

    @SuppressWarnings("unused")
    private CustomPQKemPrivateKey() {}

    public CustomPQKemPrivateKey(byte[] privateKey, OpenQuantumSafeKemNames kemName) {
        this.privateKey = privateKey;
        this.kemName = kemName;
    }

    public byte[] getPrivateKey() {
        return this.privateKey;
    }

    @Override
    public byte[] getEncoded() {
        return this.privateKey;
    }

    @Override
    public String getAlgorithm() {
        return kemName.getName();
    }
}
