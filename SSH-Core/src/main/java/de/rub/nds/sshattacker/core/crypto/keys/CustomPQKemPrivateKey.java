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
public class CustomPQKemPrivateKey extends CustomPrivateKey {
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] privateKey;

    private PQKemNames kemName;

    public CustomPQKemPrivateKey() {
        super();
    }

    public CustomPQKemPrivateKey(byte[] privateKey, PQKemNames kemName) {
        super();
        this.privateKey = privateKey;
        this.kemName = kemName;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public PQKemNames getKemName() {
        return kemName;
    }

    public void setKemName(PQKemNames kemName) {
        this.kemName = kemName;
    }

    @Override
    public byte[] getEncoded() {
        return privateKey;
    }

    @Override
    public String getAlgorithm() {
        return kemName.getName();
    }
}
