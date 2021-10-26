package de.rub.nds.sshattacker.core.util;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class RsaPublicKey extends ModifiableVariableHolder {
    private ModifiableInteger modulusLength;
    private ModifiableBigInteger modulus;

    private ModifiableInteger exponentLength;
    private ModifiableBigInteger exponent;


    public RsaPublicKey() {
    }

    // Modulus
    public ModifiableInteger getModulusLength() {
        return modulusLength;
    }

    public void setModulusLength(int modulusLength) {
        this.modulusLength = ModifiableVariableFactory.safelySetValue(this.modulusLength, modulusLength);
    }

    public void setModulusLength(ModifiableInteger modulusLength) {
        this.modulusLength = modulusLength;
    }

    public ModifiableBigInteger getModulus() {
        return modulus;
    }

    public void setModulus(byte[] nBytes) {
        BigInteger nNew = new BigInteger(Arrays.toString(nBytes), 16);
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, nNew);
    }

    public void setN(BigInteger n) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, n);
    }

    // Exponent
    public ModifiableInteger getExponentLength() {
        return exponentLength;
    }

    public void setExponentLength(int exponentLength) {
        this.exponentLength = ModifiableVariableFactory.safelySetValue(this.exponentLength, exponentLength);
    }

    public void setExponentLength(ModifiableInteger exponentLength) {
        this.exponentLength = exponentLength;
    }

    public ModifiableBigInteger getExponent() {
        return exponent;
    }

    public void setExponent(byte[] eBytes) {
        BigInteger eNew = new BigInteger(Arrays.toString(eBytes), 16);
        this.exponent = ModifiableVariableFactory.safelySetValue(this.exponent, eNew);
    }

    public void setE(BigInteger e) {
        this.exponent = ModifiableVariableFactory.safelySetValue(this.exponent, e);
    }
}
