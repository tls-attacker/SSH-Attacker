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

public class CustomRsaPublicKey extends ModifiableVariableHolder implements RSAPublicKey {

    private ModifiableInteger modulusLength;
    private ModifiableBigInteger modulus;

    private ModifiableInteger publicExponentLength;
    private ModifiableBigInteger publicExponent;

    public CustomRsaPublicKey() {}

    public CustomRsaPublicKey(BigInteger publicExponent, BigInteger modulus) {
        this.setPublicExponent(publicExponent, true);
        this.setModulus(modulus, true);
    }

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

    public ModifiableInteger getPublicExponentLength() {
        return publicExponentLength;
    }

    public void setPublicExponentLength(int exponentLength) {
        this.publicExponentLength =
                ModifiableVariableFactory.safelySetValue(this.publicExponentLength, exponentLength);
    }

    public void setPublicExponentLength(ModifiableInteger exponentLength) {
        this.publicExponentLength = exponentLength;
    }

    public ModifiableBigInteger getModifiablePublicExponent() {
        return publicExponent;
    }

    public void setPublicExponent(byte[] eBytes) {
        BigInteger newExponent = new BigInteger(Arrays.toString(eBytes), 16);
        this.publicExponent =
                ModifiableVariableFactory.safelySetValue(this.publicExponent, newExponent);
    }

    public void setPublicExponent(BigInteger exponent) {
        this.setPublicExponent(exponent, false);
    }

    public void setPublicExponent(BigInteger exponent, boolean adjustLengthField) {
        if (adjustLengthField) {
            double bitLength = exponent.bitLength();
            int byteLength = (int) Math.ceil(bitLength / 8);
            this.setPublicExponentLength(byteLength);
        }
        this.publicExponent =
                ModifiableVariableFactory.safelySetValue(this.publicExponent, exponent);
    }

    // Interface methods
    @Override
    public BigInteger getPublicExponent() {
        return publicExponent.getValue();
    }

    @Override
    public BigInteger getModulus() {
        return modulus.getValue();
    }

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
