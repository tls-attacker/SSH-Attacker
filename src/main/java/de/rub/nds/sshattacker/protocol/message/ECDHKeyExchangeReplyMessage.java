package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import java.math.BigInteger;

public class ECDHKeyExchangeReplyMessage extends BinaryPacket {

    private ModifiableInteger hostKeyLength;

    private ModifiableInteger hostKeyTypeLength;
    private ModifiableString hostKeyType;

    private ModifiableInteger exponentLength;
    private ModifiableBigInteger exponent;

    private ModifiableInteger modulusLength;
    private ModifiableBigInteger modulus;

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableByteArray ephemeralPublicKey;

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public ModifiableInteger getHostKeyTypeLength() {
        return hostKeyTypeLength;
    }

    public void setHostKeyTypeLength(ModifiableInteger hostKeyTypeLength) {
        this.hostKeyTypeLength = hostKeyTypeLength;
    }

    public void setHostKeyTypeLength(int hostKeyTypeLength) {
        this.hostKeyTypeLength = ModifiableVariableFactory.safelySetValue(this.hostKeyTypeLength, hostKeyTypeLength);
    }

    public ModifiableString getHostKeyType() {
        return hostKeyType;
    }

    public void setHostKeyType(ModifiableString hostKeyType) {
        this.hostKeyType = hostKeyType;
    }

    public void setHostKeyType(String hostKeyType) {
        this.hostKeyType = ModifiableVariableFactory.safelySetValue(this.hostKeyType, hostKeyType);
    }

    public ModifiableInteger getHostKeyLength() {
        return hostKeyLength;
    }

    public void setHostKeyLength(ModifiableInteger hostKeyLength) {
        this.hostKeyLength = hostKeyLength;
    }

    public void setHostKeyLength(int hostKeyLength) {
        this.hostKeyLength = ModifiableVariableFactory.safelySetValue(this.hostKeyLength, hostKeyLength);
    }

    public ModifiableInteger getExponentLength() {
        return exponentLength;
    }

    public void setExponentLength(ModifiableInteger exponentLength) {
        this.exponentLength = exponentLength;
    }

    public void setExponentLength(int exponentLength) {
        this.exponentLength = ModifiableVariableFactory.safelySetValue(this.exponentLength, exponentLength);
    }

    public ModifiableBigInteger getExponent() {
        return exponent;
    }

    public void setExponent(ModifiableBigInteger exponent) {
        this.exponent = exponent;
    }

    public void setExponent(BigInteger exponent) {
        this.exponent = ModifiableVariableFactory.safelySetValue(this.exponent, exponent);
    }

    public ModifiableInteger getModulusLength() {
        return modulusLength;
    }

    public void setModulusLength(ModifiableInteger modulusLength) {
        this.modulusLength = modulusLength;
    }

    public void setModulusLength(int modulusLength) {
        this.modulusLength = ModifiableVariableFactory.safelySetValue(this.modulusLength, modulusLength);
    }

    public ModifiableBigInteger getModulus() {
        return modulus;
    }

    public void setModulus(ModifiableBigInteger modulus) {
        this.modulus = modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    public ModifiableInteger getEphemeralPublicKeyLength() {
        return ephemeralPublicKeyLength;
    }

    public void setEphemeralPublicKeyLength(ModifiableInteger ephemeralPublicKeyLength) {
        this.ephemeralPublicKeyLength = ephemeralPublicKeyLength;
    }
    
    public void setEphemeralPublicKeyLength(int ephemeralPublicKeyLength) {
        this.ephemeralPublicKeyLength = ModifiableVariableFactory.safelySetValue(this.ephemeralPublicKeyLength, ephemeralPublicKeyLength);
    }

    public void setPublicKeyLength(int publicKeyLength) {
        this.ephemeralPublicKeyLength = ModifiableVariableFactory.safelySetValue(this.ephemeralPublicKeyLength, publicKeyLength);
    }

    public ModifiableByteArray getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(ModifiableByteArray ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }
    
    public void setEphemeralPublicKey(byte[] ephemeralPublicKey) {
        this.ephemeralPublicKey = ModifiableVariableFactory.safelySetValue(this.ephemeralPublicKey,ephemeralPublicKey);
    }

    public void setPublicKey(byte[] publicKey) {
        this.ephemeralPublicKey = ModifiableVariableFactory.safelySetValue(this.ephemeralPublicKey, publicKey);
    }

    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int signatureLength) {
        this.signatureLength = ModifiableVariableFactory.safelySetValue(this.signatureLength, signatureLength);
    }

    public ModifiableByteArray getSignature() {
        return signature;
    }

    public void setSignature(ModifiableByteArray signature) {
        this.signature = signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }
}
