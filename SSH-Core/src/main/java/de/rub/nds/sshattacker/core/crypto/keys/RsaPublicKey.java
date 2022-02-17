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
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class RsaPublicKey extends ModifiableVariableHolder implements RSAPublicKey {
    private ModifiableInteger modulusLength;
    private ModifiableBigInteger modulus;

    private ModifiableInteger exponentLength;
    private ModifiableBigInteger exponent;

    public RsaPublicKey() {}

    public RsaPublicKey(BigInteger exponent, BigInteger modulus) {
        this.setExponent(exponent, true);
        this.setModulus(modulus, true);
    }

    // Modulus
    public ModifiableInteger getModulusLength() {
        return modulusLength;
    }

    public void setModulusLength(int modulusLength) {
        this.modulusLength =
                ModifiableVariableFactory.safelySetValue(this.modulusLength, modulusLength);
    }

    public void setModulusLength(ModifiableInteger modulusLength) {
        this.modulusLength = modulusLength;
    }

    public ModifiableBigInteger getModifiableModulus() {
        return modulus;
    }

    @Override
    public BigInteger getModulus() {
        return modulus.getValue();
    }

    public void setModulus(byte[] nBytes) {
        BigInteger newModulus = new BigInteger(Arrays.toString(nBytes), 16);
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, newModulus);
    }

    public void setModulus(BigInteger modulus) {
        this.setModulus(modulus, false);
    }

    public void setModulus(BigInteger modulus, boolean adjustLengthField) {
        if (adjustLengthField) {
            double bitLength = modulus.bitLength();
            int byteLength = (int) Math.ceil(bitLength / 8);
            this.setModulusLength(byteLength);
        }
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    // Exponent
    public ModifiableInteger getExponentLength() {
        return exponentLength;
    }

    public void setExponentLength(int exponentLength) {
        this.exponentLength =
                ModifiableVariableFactory.safelySetValue(this.exponentLength, exponentLength);
    }

    public void setExponentLength(ModifiableInteger exponentLength) {
        this.exponentLength = exponentLength;
    }

    public ModifiableBigInteger getExponent() {
        return exponent;
    }

    @Override
    public BigInteger getPublicExponent() {
        return exponent.getValue();
    }

    public void setExponent(byte[] eBytes) {
        BigInteger newExponent = new BigInteger(Arrays.toString(eBytes), 16);
        this.exponent = ModifiableVariableFactory.safelySetValue(this.exponent, newExponent);
    }

    public void setExponent(BigInteger exponent) {
        this.setExponent(exponent, false);
    }

    public void setExponent(BigInteger exponent, boolean adjustLengthField) {
        if (adjustLengthField) {
            double bitLength = exponent.bitLength();
            int byteLength = (int) Math.ceil(bitLength / 8);
            this.setExponentLength(byteLength);
        }
        this.exponent = ModifiableVariableFactory.safelySetValue(this.exponent, exponent);
    }

    // Interface methods
    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return null;
    }
}
