/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.sshattacker.core.constants.PQKemNames;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomPQKemPublicKey extends CustomPublicKey {
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] publicKey;

    private PQKemNames kemName;

    public CustomPQKemPublicKey() {
        super();
    }

    public CustomPQKemPublicKey(byte[] publicKey, PQKemNames kemName) {
        super();
        this.publicKey = publicKey;
        this.kemName = kemName;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public PQKemNames getKemName() {
        return kemName;
    }

    public void setKemName(PQKemNames kemName) {
        this.kemName = kemName;
    }

    @Override
    public byte[] getEncoded() {
        return publicKey;
    }

    @Override
    public String getAlgorithm() {
        return kemName.getName();
    }
}
