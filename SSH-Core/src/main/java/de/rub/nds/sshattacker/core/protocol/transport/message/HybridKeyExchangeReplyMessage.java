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
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.HybridKeyExchangeReplyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class HybridKeyExchangeReplyMessage extends SshMessage<HybridKeyExchangeReplyMessage>
        implements HostKeyMessage, ExchangeHashSignatureMessage, HasSentHandler {

    private ModifiableInteger hostKeyBytesLength;
    private ModifiableByteArray hostKeyBytes;

    private ModifiableInteger concatenatedHybridKeysLength;
    private ModifiableByteArray concatenatedHybridKeys;

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public HybridKeyExchangeReplyMessage() {
        super();
    }

    public HybridKeyExchangeReplyMessage(HybridKeyExchangeReplyMessage other) {
        super(other);
        hostKeyBytesLength =
                other.hostKeyBytesLength != null ? other.hostKeyBytesLength.createCopy() : null;
        hostKeyBytes = other.hostKeyBytes != null ? other.hostKeyBytes.createCopy() : null;
        concatenatedHybridKeysLength =
                other.concatenatedHybridKeysLength != null
                        ? other.concatenatedHybridKeysLength.createCopy()
                        : null;
        concatenatedHybridKeys =
                other.concatenatedHybridKeys != null
                        ? other.concatenatedHybridKeys.createCopy()
                        : null;
        signatureLength = other.signatureLength != null ? other.signatureLength.createCopy() : null;
        signature = other.signature != null ? other.signature.createCopy() : null;
    }

    @Override
    public HybridKeyExchangeReplyMessage createCopy() {
        return new HybridKeyExchangeReplyMessage(this);
    }

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

    public ModifiableInteger getConcatenatedHybridKeysLength() {
        return concatenatedHybridKeysLength;
    }

    public void setConcatenatedHybridKeysLength(ModifiableInteger concatenatedHybridKeysLength) {
        this.concatenatedHybridKeysLength = concatenatedHybridKeysLength;
    }

    public void setConcatenatedHybridKeysLength(int concatenatedHybridKeysLength) {
        this.concatenatedHybridKeysLength =
                ModifiableVariableFactory.safelySetValue(
                        this.concatenatedHybridKeysLength, concatenatedHybridKeysLength);
    }

    public ModifiableByteArray getConcatenatedHybridKeys() {
        return concatenatedHybridKeys;
    }

    public void setConcatenatedHybridKeys(byte[] concatenatedHybridKeys) {
        setConcatenatedHybridKeys(concatenatedHybridKeys, false);
    }

    public void setConcatenatedHybridKeys(
            ModifiableByteArray concatenatedHybridKeys, boolean adjustLengthField) {
        this.concatenatedHybridKeys = concatenatedHybridKeys;
        if (adjustLengthField) {
            setConcatenatedHybridKeysLength(this.concatenatedHybridKeys.getValue().length);
        }
    }

    public void setConcatenatedHybridKeys(
            byte[] concatenatedHybridKeys, boolean adjustLengthField) {
        this.concatenatedHybridKeys =
                ModifiableVariableFactory.safelySetValue(
                        this.concatenatedHybridKeys, concatenatedHybridKeys);
        if (adjustLengthField) {
            setConcatenatedHybridKeysLength(this.concatenatedHybridKeys.getValue().length);
        }
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

    public static final HybridKeyExchangeReplyMessageHandler HANDLER =
            new HybridKeyExchangeReplyMessageHandler();

    @Override
    public HybridKeyExchangeReplyMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        HybridKeyExchangeReplyMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return HybridKeyExchangeReplyMessageHandler.SERIALIZER.serialize(this);
    }
}
