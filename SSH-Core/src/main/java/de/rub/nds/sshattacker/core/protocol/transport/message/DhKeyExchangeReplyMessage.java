/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhKeyExchangeReplyMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.math.BigInteger;

public class DhKeyExchangeReplyMessage extends Message<DhKeyExchangeReplyMessage> {

    private ModifiableInteger hostKeyLength;
    private ModifiableByteArray hostKey;

    // TODO: Interpret host key

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableBigInteger ephemeralPublicKey;

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public DhKeyExchangeReplyMessage() {
        super(MessageIDConstant.SSH_MSG_KEXDH_REPLY);
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

    public ModifiableByteArray getHostKey() {
        return hostKey;
    }

    public void setHostKey(ModifiableByteArray hostKey) {
        setHostKey(hostKey, false);
    }

    public void setHostKey(byte[] hostKey) {
        setHostKey(hostKey, false);
    }

    public void setHostKey(ModifiableByteArray hostKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setHostKeyLength(hostKey.getValue().length);
        }
        this.hostKey = hostKey;
    }

    public void setHostKey(byte[] hostKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setHostKeyLength(hostKey.length);
        }
        this.hostKey = ModifiableVariableFactory.safelySetValue(this.hostKey, hostKey);
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
        setEphemeralPublicKey(ephemeralPublicKey, false);
    }

    public void setEphemeralPublicKey(BigInteger ephemeralPublicKey) {
        setEphemeralPublicKey(ephemeralPublicKey, false);
    }

    public void setEphemeralPublicKey(ModifiableBigInteger ephemeralPublicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(ephemeralPublicKey.getValue().toByteArray().length);
        }
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(BigInteger ephemeralPublicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(ephemeralPublicKey.toByteArray().length);
        }
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
        setSignature(signature, false);
    }

    public void setSignature(byte[] signature) {
        setSignature(signature, false);
    }

    public void setSignature(ModifiableByteArray signature, boolean adjustLengthField) {
        if (adjustLengthField) {
            setSignatureLength(signature.getValue().length);
        }
        this.signature = signature;
    }

    public void setSignature(byte[] signature, boolean adjustLengthField) {
        if (adjustLengthField) {
            setSignatureLength(signature.length);
        }
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
}
