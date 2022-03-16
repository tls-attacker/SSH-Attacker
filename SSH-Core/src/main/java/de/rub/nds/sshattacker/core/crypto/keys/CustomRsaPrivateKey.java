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
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

public class CustomRsaPrivateKey extends ModifiableVariableHolder implements RSAPrivateKey {

    private ModifiableBigInteger privateExponent;
    private ModifiableBigInteger modulus;

    public CustomRsaPrivateKey() {}

    public CustomRsaPrivateKey(BigInteger privateExponent, BigInteger modulus) {
        setPrivateExponent(privateExponent);
        setModulus(modulus);
    }

    public ModifiableBigInteger getModifiableModulus() {
        return modulus;
    }

    public void setModulus(byte[] nBytes) {
        BigInteger newModulus = new BigInteger(Arrays.toString(nBytes), 16);
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, newModulus);
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    public void setModulus(ModifiableBigInteger modulus) {
        this.modulus = modulus;
    }

    public ModifiableBigInteger getModifiablePrivateExponent() {
        return privateExponent;
    }

    public void setPrivateExponent(byte[] dBytes) {
        BigInteger newExponent = new BigInteger(Arrays.toString(dBytes), 16);
        this.privateExponent =
                ModifiableVariableFactory.safelySetValue(this.privateExponent, newExponent);
    }

    public void setPrivateExponent(BigInteger exponent) {
        this.privateExponent =
                ModifiableVariableFactory.safelySetValue(this.privateExponent, exponent);
    }

    public void setPrivateExponent(ModifiableBigInteger exponent) {
        this.privateExponent = exponent;
    }

    // Interface methods
    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent.getValue();
    }

    @Override
    public BigInteger getModulus() {
        return modulus.getValue();
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}
