/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;

public class CustomDsaPublicKey extends ModifiableVariableHolder implements DSAPublicKey {

    // Group parameters
    private ModifiableInteger pLength;
    private ModifiableBigInteger p;
    private ModifiableInteger qLength;
    private ModifiableBigInteger q;
    private ModifiableInteger gLength;
    private ModifiableBigInteger g;

    // Public key
    private ModifiableInteger yLength;
    private ModifiableBigInteger y;

    public CustomDsaPublicKey() {}

    public CustomDsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        this.setP(p, true);
        this.setQ(q, true);
        this.setG(g, true);
        this.setY(y, true);
    }

    public ModifiableInteger getPLength() {
        return pLength;
    }

    public void setPLength(int pLength) {
        this.pLength = ModifiableVariableFactory.safelySetValue(this.pLength, pLength);
    }

    public void setPLength(ModifiableInteger pLength) {
        this.pLength = pLength;
    }

    public BigInteger getP() {
        return p.getValue();
    }

    public ModifiableBigInteger getModifiableP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.setP(p, false);
    }

    public void setP(BigInteger p, boolean adjustLengthField) {
        if (adjustLengthField) {
            this.setPLength(p.toByteArray().length);
        }
        this.p = ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    public ModifiableInteger getQLength() {
        return qLength;
    }

    public void setQLength(int qLength) {
        this.qLength = ModifiableVariableFactory.safelySetValue(this.qLength, qLength);
    }

    public void setQLength(ModifiableInteger qLength) {
        this.qLength = qLength;
    }

    public BigInteger getQ() {
        return q.getValue();
    }

    public ModifiableBigInteger getModifiableQ() {
        return q;
    }

    public void setQ(BigInteger q) {
        this.setQ(q, false);
    }

    public void setQ(BigInteger q, boolean adjustLengthField) {
        if (adjustLengthField) {
            this.setQLength(q.toByteArray().length);
        }
        this.q = ModifiableVariableFactory.safelySetValue(this.q, q);
    }

    public ModifiableInteger getGLength() {
        return gLength;
    }

    public void setGLength(int gLength) {
        this.gLength = ModifiableVariableFactory.safelySetValue(this.gLength, gLength);
    }

    public void setGLength(ModifiableInteger gLength) {
        this.gLength = gLength;
    }

    public BigInteger getG() {
        return g.getValue();
    }

    public ModifiableBigInteger getModifiableG() {
        return g;
    }

    public void setG(BigInteger g) {
        this.setG(g, false);
    }

    public void setG(BigInteger g, boolean adjustLengthField) {
        if (adjustLengthField) {
            this.setGLength(g.toByteArray().length);
        }
        this.g = ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    public ModifiableInteger getYLength() {
        return yLength;
    }

    public void setYLength(int yLength) {
        this.yLength = ModifiableVariableFactory.safelySetValue(this.yLength, yLength);
    }

    public void setYLength(ModifiableInteger yLength) {
        this.yLength = yLength;
    }

    public ModifiableBigInteger getModifiableY() {
        return y;
    }

    public void setY(BigInteger y) {
        this.setY(y, false);
    }

    public void setY(BigInteger y, boolean adjustLengthField) {
        if (adjustLengthField) {
            this.setYLength(y.toByteArray().length);
        }
        this.y = ModifiableVariableFactory.safelySetValue(this.y, y);
    }

    // Interface methods
    @Override
    public BigInteger getY() {
        return y.getValue();
    }

    @Override
    public DSAParams getParams() {
        return new DSAParameterSpec(p.getValue(), q.getValue(), g.getValue());
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public String getFormat() {
        return null;
    }
}
