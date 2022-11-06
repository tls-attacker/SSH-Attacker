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
public class CustomSntrup761PublicKey extends CustomPublicKey {

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] publicKey;

    @SuppressWarnings("unused")
    public CustomSntrup761PublicKey() {}
    ;

    public CustomSntrup761PublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getPublicKey() {
        return this.publicKey;
    }

    @Override
    public byte[] getEncoded() {
        return this.publicKey;
    }

    @Override
    public String getAlgorithm() {
        return "SNTRUP761";
    }
}
