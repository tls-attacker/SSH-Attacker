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
import jakarta.xml.bind.annotation.XmlRootElement;



@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomPQKemPublicKey extends CustomPublicKey {


    private byte[] publicKey;
    private String algorithm;
    
    @SuppressWarnings("unused")
    public CustomPQKemPublicKey() {}

    public CustomPQKemPublicKey(byte[] publicKey, String algorithm) {
        this.publicKey = publicKey;
        this.algorithm = algorithm;
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
        return algorithm;
    }
}