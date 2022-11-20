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
import de.rub.nds.sshattacker.core.protocol.transport.handler.Sntrup761X25519KeyExchangeReplyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class HybridKeyExchangeReplyMessage
        extends SshMessage<HybridKeyExchangeReplyMessage>
        implements HostKeyMessage, ExchangeHashSignatureMessage {


    private ModifiableInteger hostKeyBytesLength;
    private ModifiableByteArray hostKeyBytes;

    private ModifiableInteger hybridKeyLength;
    private ModifiableByteArray hybridKey;

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
        if (adjustLengthField) {
            setHostKeyBytesLength(hostKeyBytes.getValue().length);
        }
        this.hostKeyBytes = hostKeyBytes;
    }

    @Override
    public void setHostKeyBytes(byte[] hostKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setHostKeyBytesLength(hostKey.length);
        }
        this.hostKeyBytes = ModifiableVariableFactory.safelySetValue(this.hostKeyBytes, hostKey);
    }

    public ModifiableInteger getHybridKeyLength() {
        return hybridKeyLength;
    }

    public void setHybridKeyLength(ModifiableInteger hybridKeyLength) {
        this.hybridKeyLength = hybridKeyLength;
    }

    public void setHybridKeyLength(int hybridKeyLength) {
        this.hybridKeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.hybridKeyLength, hybridKeyLength);
    }

    public ModifiableByteArray getHybridKey() {
        return hybridKey;
    }

    public void setHybridKey(byte[] hybridKey) {
        setHybridKey(hybridKey, false);
    }

    public void setHybridKey(
            ModifiableByteArray hybridKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setHybridKeyLength(hybridKey.getValue().length);
        }
        this.hybridKey = hybridKey;
    }

    public void setHybridKey(byte[] hybridKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setHybridKeyLength(hybridKey.length);
        }
        this.hybridKey =
                ModifiableVariableFactory.safelySetValue(
                        this.hybridKey, hybridKey);
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
        if (adjustLengthField) {
            setSignatureLength(signature.getValue().length);
        }
        this.signature = signature;
    }

    @Override
    public void setSignature(byte[] signature, boolean adjustLengthField) {
        if (adjustLengthField) {
            setSignatureLength(signature.length);
        }
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }

    @Override
    public Sntrup761X25519KeyExchangeReplyMessageHandler getHandler(SshContext context) {
        return new Sntrup761X25519KeyExchangeReplyMessageHandler(context, this);
    }
}
