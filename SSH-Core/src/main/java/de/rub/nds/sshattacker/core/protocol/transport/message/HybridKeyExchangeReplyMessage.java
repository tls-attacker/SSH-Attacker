/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.HybridKeyExchangeReplyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class HybridKeyExchangeReplyMessage extends SshMessage<HybridKeyExchangeReplyMessage>
        implements HostKeyMessage, ExchangeHashSignatureMessage {

    private ModifiableInteger hostKeyBytesLength;
    private ModifiableByteArray hostKeyBytes;

    private ModifiableInteger publicValuesLength;
    private ModifiableByteArray publicValues;

    private ModifiableByteArray classicalPublicKey;
    private ModifiableByteArray postQuantumKeyEncapsulation;

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    @Override
    public ModifiableInteger getHostKeyBytesLength() {
        return hostKeyBytesLength;
    }

    @Override
    public void setHostKeyBytesLength(ModifiableInteger hostKeyBytesLength) {
        this.hostKeyBytesLength = hostKeyBytesLength;
    }

    @Override
    public void setHostKeyBytesLength(int hostKeyBytesLength) {
        this.hostKeyBytesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.hostKeyBytesLength, hostKeyBytesLength);
    }

    @Override
    public ModifiableByteArray getHostKeyBytes() {
        return hostKeyBytes;
    }

    @Override
    public SshPublicKey<?, ?> getHostKey() {
        return PublicKeyHelper.parse(hostKeyBytes.getValue());
    }

    @Override
    public void setHostKeyBytes(ModifiableByteArray hostKeyBytes) {
        setHostKeyBytes(hostKeyBytes, false);
    }

    @Override
    public void setHostKeyBytes(byte[] hostKeyBytes) {
        setHostKeyBytes(hostKeyBytes, false);
    }

    @Override
    public void setHostKeyBytes(ModifiableByteArray hostKeyBytes, boolean adjustLengthField) {
        this.hostKeyBytes = hostKeyBytes;
        if (adjustLengthField) {
            setHostKeyBytesLength(this.hostKeyBytes.getValue().length);
        }
    }

    @Override
    public void setHostKeyBytes(byte[] hostKeyBytes, boolean adjustLengthField) {
        this.hostKeyBytes =
                ModifiableVariableFactory.safelySetValue(this.hostKeyBytes, hostKeyBytes);
        if (adjustLengthField) {
            setHostKeyBytesLength(this.hostKeyBytes.getValue().length);
        }
    }

    public ModifiableInteger getPublicValuesLength() {
        return publicValuesLength;
    }

    public void setPublicValuesLength(ModifiableInteger publicValuesLength) {
        this.publicValuesLength = publicValuesLength;
    }

    public void setPublicValuesLength(int publicValuesLength) {
        this.publicValuesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.publicValuesLength, publicValuesLength);
    }

    public ModifiableByteArray getPublicValues() {
        return publicValues;
    }

    public void setPublicValues(ModifiableByteArray publicValues) {
        setPublicValues(publicValues, false);
    }

    public void setPublicValues(byte[] publicValues) {
        setPublicValues(publicValues, false);
    }

    public void setPublicValues(ModifiableByteArray publicValues, boolean adjustLengthField) {
        this.publicValues = publicValues;
        if (adjustLengthField) {
            setPublicValuesLength(this.publicValues.getValue().length);
        }
    }

    public void setPublicValues(byte[] publicValues, boolean adjustLengthField) {
        this.publicValues =
                ModifiableVariableFactory.safelySetValue(this.publicValues, publicValues);
        if (adjustLengthField) {
            setPublicValuesLength(this.publicValues.getValue().length);
        }
    }

    public ModifiableByteArray getClassicalPublicKey() {
        return classicalPublicKey;
    }

    public void setClassicalPublicKey(ModifiableByteArray classicalPublicKey) {
        this.classicalPublicKey = classicalPublicKey;
    }

    public void setClassicalPublicKey(byte[] classicalPublicKey) {
        this.classicalPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.classicalPublicKey, classicalPublicKey);
    }

    public ModifiableByteArray getPostQuantumKeyEncapsulation() {
        return postQuantumKeyEncapsulation;
    }

    public void setPostQuantumKeyEncapsulation(ModifiableByteArray postQuantumKeyEncapsulation) {
        this.postQuantumKeyEncapsulation = postQuantumKeyEncapsulation;
    }

    public void setPostQuantumKeyEncapsulation(byte[] postQuantumKeyEncapsulation) {
        this.postQuantumKeyEncapsulation =
                ModifiableVariableFactory.safelySetValue(
                        this.postQuantumKeyEncapsulation, postQuantumKeyEncapsulation);
    }

    @Override
    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    @Override
    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    @Override
    public void setSignatureLength(int signatureLength) {
        this.signatureLength =
                ModifiableVariableFactory.safelySetValue(this.signatureLength, signatureLength);
    }

    @Override
    public ModifiableByteArray getSignature() {
        return signature;
    }

    @Override
    public void setSignature(ModifiableByteArray signature) {
        setSignature(signature, false);
    }

    @Override
    public void setSignature(byte[] signature) {
        setSignature(signature, false);
    }

    @Override
    public void setSignature(ModifiableByteArray signature, boolean adjustLengthField) {
        this.signature = signature;
        if (adjustLengthField) {
            setSignatureLength(this.signature.getValue().length);
        }
    }

    @Override
    public void setSignature(byte[] signature, boolean adjustLengthField) {
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
        if (adjustLengthField) {
            setSignatureLength(this.signature.getValue().length);
        }
    }

    @Override
    public HybridKeyExchangeReplyMessageHandler getHandler(SshContext context) {
        return new HybridKeyExchangeReplyMessageHandler(context, this);
    }
}
