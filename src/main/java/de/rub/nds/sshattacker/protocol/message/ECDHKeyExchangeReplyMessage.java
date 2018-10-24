package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;

public class ECDHKeyExchangeReplyMessage {

    private ModifiableInteger hostKeyLength;

    private ModifiableInteger hostKeyTypeLength;
    private ModifiableString hostKeyType;

    private ModifiableInteger exponentLength;
    private ModifiableByteArray exponent;

    private ModifiableInteger modulusLength;
    private ModifiableByteArray modulus;

    private ModifiableInteger publicKeyLength;
    private ModifiableByteArray publicKey;

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

    public ModifiableByteArray getExponent() {
        return exponent;
    }

    public void setExponent(ModifiableByteArray exponent) {
        this.exponent = exponent;
    }

    public void setExponent(byte[] exponent) {
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

    public ModifiableByteArray getModulus() {
        return modulus;
    }

    public void setModulus(ModifiableByteArray modulus) {
        this.modulus = modulus;
    }

    public void setModulus(byte[] modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    public ModifiableInteger getPublicKeyLength() {
        return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int publicKeyLength) {
        this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
    }

    public ModifiableByteArray getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ModifiableByteArray publicKey) {
        this.publicKey = publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
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
