/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomFrodoKem1344PrivateKey extends CustomPrivateKey {

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] privateKey;

    @SuppressWarnings("unused")
    private CustomFrodoKem1344PrivateKey() {}
    ;

    public CustomFrodoKem1344PrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
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
        return "FRODOKEM1344";
    }
}
