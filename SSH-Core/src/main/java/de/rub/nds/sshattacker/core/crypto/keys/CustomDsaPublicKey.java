/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/** A serializable DSA public key used in the DSA signature algorithm. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomDsaPublicKey extends CustomPublicKey implements DSAPublicKey {

    // Group parameters
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    // Public key
    private BigInteger y;

    @SuppressWarnings("unused")
    public CustomDsaPublicKey() {}

    public CustomDsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.y = y;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getQ() {
        return q;
    }

    public void setQ(BigInteger q) {
        this.q = q;
    }

    public BigInteger getG() {
        return g;
    }

    public void setG(BigInteger g) {
        this.g = g;
    }

    @Override
    public BigInteger getY() {
        return y;
    }

    public void setY(BigInteger y) {
        this.y = y;
    }

    // Interface methods
    @Override
    public DSAParams getParams() {
        return new DSAParameterSpec(p, q, g);
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }
}
