/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.handler.DhKeyExchangeReplyMessageHandler;
import de.rub.nds.sshattacker.core.protocol.handler.Handler;
import de.rub.nds.sshattacker.core.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.core.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.math.BigInteger;

public class DhKeyExchangeReplyMessage extends Message<DhKeyExchangeReplyMessage> {

    private ModifiableInteger hostKeyLength;

    private ModifiableInteger hostKeyTypeLength;
    private ModifiableString hostKeyType;

    private ModifiableInteger hostKeyRsaExponentLength;
    private ModifiableBigInteger hostKeyRsaExponent;

    private ModifiableInteger hostKeyRsaModulusLength;
    private ModifiableBigInteger hostKeyRsaModulus;

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableBigInteger ephemeralPublicKey;

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public ModifiableInteger getHostKeyLength() {
        return hostKeyLength;
    }

    public void setHostKeyLength(ModifiableInteger hostKeyLength) {
        this.hostKeyLength = hostKeyLength;
    }

    public void setHostKeyLength(int hostKeyLength) {
        this.hostKeyLength = ModifiableVariableFactory.safelySetValue(this.hostKeyLength, hostKeyLength);
    }

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

    public ModifiableInteger getHostKeyRsaExponentLength() {
        return hostKeyRsaExponentLength;
    }

    public void setHostKeyRsaExponentLength(ModifiableInteger hostKeyRsaExponentLength) {
        this.hostKeyRsaExponentLength = hostKeyRsaExponentLength;
    }

    public void setHostKeyRsaExponentLength(int hostKeyRsaExponentLength) {
        this.hostKeyRsaExponentLength = ModifiableVariableFactory.safelySetValue(this.hostKeyRsaExponentLength,
                hostKeyRsaExponentLength);
    }

    public ModifiableBigInteger getHostKeyRsaExponent() {
        return hostKeyRsaExponent;
    }

    public void setHostKeyRsaExponent(ModifiableBigInteger hostKeyRsaExponent) {
        this.hostKeyRsaExponent = hostKeyRsaExponent;
    }

    public void setHostKeyRsaExponent(BigInteger hostKeyRsaExponent) {
        this.hostKeyRsaExponent = ModifiableVariableFactory.safelySetValue(this.hostKeyRsaExponent, hostKeyRsaExponent);
    }

    public ModifiableInteger getHostKeyRsaModulusLength() {
        return hostKeyRsaModulusLength;
    }

    public void setHostKeyRsaModulusLength(ModifiableInteger hostKeyRsaModulusLength) {
        this.hostKeyRsaModulusLength = hostKeyRsaModulusLength;
    }

    public void setHostKeyRsaModulusLength(int hostKeyRsaModulusLength) {
        this.hostKeyRsaModulusLength = ModifiableVariableFactory.safelySetValue(this.hostKeyRsaModulusLength,
                hostKeyRsaModulusLength);
    }

    public ModifiableBigInteger getHostKeyRsaModulus() {
        return hostKeyRsaModulus;
    }

    public void setHostKeyRsaModulus(ModifiableBigInteger hostKeyRsaModulus) {
        this.hostKeyRsaModulus = hostKeyRsaModulus;
    }

    public void setHostKeyRsaModulus(BigInteger hostKeyRsaModulus) {
        this.hostKeyRsaModulus = ModifiableVariableFactory.safelySetValue(this.hostKeyRsaModulus, hostKeyRsaModulus);
    }

    public ModifiableInteger getEphemeralPublicKeyLength() {
        return ephemeralPublicKeyLength;
    }

    public void setEphemeralPublicKeyLength(ModifiableInteger ephemeralPublicKeyLength) {
        this.ephemeralPublicKeyLength = ephemeralPublicKeyLength;
    }

    public void setEphemeralPublicKeyLength(int ephemeralPublicKeyLength) {
        this.ephemeralPublicKeyLength = ModifiableVariableFactory.safelySetValue(this.ephemeralPublicKeyLength,
                ephemeralPublicKeyLength);
    }

    public ModifiableBigInteger getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(ModifiableBigInteger ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(BigInteger ephemeralPublicKey) {
        this.ephemeralPublicKey = ModifiableVariableFactory.safelySetValue(this.ephemeralPublicKey, ephemeralPublicKey);
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

    @Override
    public Handler<DhKeyExchangeReplyMessage> getHandler(SshContext context) {
        return new DhKeyExchangeReplyMessageHandler(context);
    }

    @Override
    public Serializer<DhKeyExchangeReplyMessage> getSerializer() {
        // TODO: Implement DHKeyExchangeReplyMessageSerializer
        throw new NotImplementedException("DHKeyExchangeReplyMessage::getSerializer");
    }

    @Override
    public Preparator<DhKeyExchangeReplyMessage> getPreparator(SshContext context) {
        // TODO: Implement DHKeyExchangeReplyMessagePreparator
        throw new NotImplementedException("DHKeyExchangeReplyMessage::getPreparator");
    }

    @Override
    public String toCompactString() {
        return "DHKeyExchangeReplyMessage";
    }
}
