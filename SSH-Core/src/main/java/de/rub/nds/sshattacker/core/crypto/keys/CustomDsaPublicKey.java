/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;

/** A serializable DSA public key used in the DSA signature algorithm. */
@XmlRootElement
public class CustomDsaPublicKey extends CustomPublicKey implements DSAPublicKey {

    // Group parameters
    protected BigInteger p;
    protected BigInteger q;
    protected BigInteger g;

    // Public key
    protected BigInteger y;

    public CustomDsaPublicKey() {
        super();
    }

    public CustomDsaPublicKey(DSAPublicKey publicKey) {
        super();
        p = publicKey.getParams().getP();
        q = publicKey.getParams().getQ();
        g = publicKey.getParams().getG();
        y = publicKey.getY();
    }

    public CustomDsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        super();
        this.p = p;
        this.q = q;
        this.g = g;
        this.y = y;
    }

    public CustomDsaPublicKey(CustomDsaPublicKey other) {
        super(other);
        p = other.p;
        q = other.q;
        g = other.g;
        y = other.y;
    }

    @Override
    public CustomDsaPublicKey createCopy() {
        return new CustomDsaPublicKey(this);
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
