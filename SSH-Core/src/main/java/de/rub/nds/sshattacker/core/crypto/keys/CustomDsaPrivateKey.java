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
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;
import java.util.Objects;

/** A serializable DSA private key used in the DSA signature algorithm. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomDsaPrivateKey extends CustomPrivateKey implements DSAPrivateKey {

    // Group parameters
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    // Private key
    private BigInteger x;

    public CustomDsaPrivateKey() {
        super();
    }

    public CustomDsaPrivateKey(BigInteger p, BigInteger q, BigInteger g, BigInteger x) {
        super();
        this.p = p;
        this.q = q;
        this.g = g;
        this.x = x;
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
    public BigInteger getX() {
        return x;
    }

    public void setX(BigInteger x) {
        this.x = x;
    }

    // Interface methods
    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public DSAParams getParams() {
        return new DSAParameterSpec(p, q, g);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CustomDsaPrivateKey that = (CustomDsaPrivateKey) o;
        return Objects.equals(p, that.p)
                && Objects.equals(q, that.q)
                && Objects.equals(g, that.g)
                && Objects.equals(x, that.x);
    }

    @Override
    public int hashCode() {
        return Objects.hash(p, q, g, x);
    }
}
