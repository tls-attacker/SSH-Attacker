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

    private ModifiableInteger hostKeyRsaExponentLength;
    private ModifiableBigInteger hostKeyRsaExponent;

    private ModifiableInteger hostKeyRsaModulusLength;
    private ModifiableBigInteger hostKeyRsaModulus;
    
    private ModifiableInteger eccCurveIdentifierLength;
    private ModifiableString eccCurveIdentifier;
    private ModifiableInteger hostKeyEccLength;
    private ModifiableByteArray hostKeyEcc;

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

    public ModifiableInteger getHostKeyRsaExponentLength() {
        return hostKeyRsaExponentLength;
    }

    public void setHostKeyRsaExponentLength(ModifiableInteger hostKeyRsaExponentLength) {
        this.hostKeyRsaExponentLength = hostKeyRsaExponentLength;
    }

    public void setExponentLength(int exponentLength) {
        this.hostKeyRsaExponentLength = ModifiableVariableFactory.safelySetValue(this.hostKeyRsaExponentLength, exponentLength);
    }

    public ModifiableBigInteger getHostKeyRsaExponent() {
        return hostKeyRsaExponent;
    }

    public void setHostKeyRsaExponent(ModifiableBigInteger hostKeyRsaExponent) {
        this.hostKeyRsaExponent = hostKeyRsaExponent;
    }

    public void setExponent(BigInteger exponent) {
        this.hostKeyRsaExponent = ModifiableVariableFactory.safelySetValue(this.hostKeyRsaExponent, exponent);
    }

    public ModifiableInteger getHostKeyRsaModulusLength() {
        return hostKeyRsaModulusLength;
    }

    public void setHostKeyRsaModulusLength(ModifiableInteger hostKeyRsaModulusLength) {
        this.hostKeyRsaModulusLength = hostKeyRsaModulusLength;
    }

    public void setModulusLength(int modulusLength) {
        this.hostKeyRsaModulusLength = ModifiableVariableFactory.safelySetValue(this.hostKeyRsaModulusLength, modulusLength);
    }

    public ModifiableBigInteger getHostKeyRsaModulus() {
        return hostKeyRsaModulus;
    }

    public void setHostKeyRsaModulus(ModifiableBigInteger hostKeyRsaModulus) {
        this.hostKeyRsaModulus = hostKeyRsaModulus;
    }

    public void setModulus(BigInteger modulus) {
        this.hostKeyRsaModulus = ModifiableVariableFactory.safelySetValue(this.hostKeyRsaModulus, modulus);
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

    public ModifiableInteger getHostKeyEccLength() {
        return hostKeyEccLength;
    }

    public void setHostKeyEccLength(ModifiableInteger hostKeyEccLength) {
        this.hostKeyEccLength = hostKeyEccLength;
    }
    
    public void setHostKeyEccLength(int hostKeyEccLength) {
        this.hostKeyEccLength = ModifiableVariableFactory.safelySetValue(this.hostKeyEccLength, hostKeyEccLength);
    }

    public ModifiableByteArray getHostKeyEcc() {
        return hostKeyEcc;
    }

    public void setHostKeyEcc(ModifiableByteArray hostKeyEcc) {
        this.hostKeyEcc = hostKeyEcc;
    }
    
    public void setHostKeyEcc(byte[] hostKeyEcc) {
        this.hostKeyEcc = ModifiableVariableFactory.safelySetValue(this.hostKeyEcc, hostKeyEcc);
    }

    public ModifiableInteger getEccCurveIdentifierLength() {
        return eccCurveIdentifierLength;
    }

    public void setEccCurveIdentifierLength(ModifiableInteger eccCurveIdentifierLength) {
        this.eccCurveIdentifierLength = eccCurveIdentifierLength;
    }
    
    public void setEccCurveIdentifierLength(int eccCurveIdentifierLength) {
        this.eccCurveIdentifierLength = ModifiableVariableFactory.safelySetValue(this.eccCurveIdentifierLength, eccCurveIdentifierLength);
    }

    public ModifiableString getEccCurveIdentifier() {
        return eccCurveIdentifier;
    }

    public void setEccCurveIdentifier(ModifiableString eccCurveIdentifier) {
        this.eccCurveIdentifier = eccCurveIdentifier;
    }
    
    public void setEccCurveIdentifier(String eccCurveIdentifier) {
        this.eccCurveIdentifier = ModifiableVariableFactory.safelySetValue(this.eccCurveIdentifier, eccCurveIdentifier);
    }
}
