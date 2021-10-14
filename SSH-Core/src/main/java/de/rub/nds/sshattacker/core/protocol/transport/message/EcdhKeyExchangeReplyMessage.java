/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.EcdhKeyExchangeReplyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class EcdhKeyExchangeReplyMessage extends SshMessage<EcdhKeyExchangeReplyMessage> {

    private ModifiableInteger hostKeyLength;
    private ModifiableByteArray hostKey;

    // TODO: Interpret host key

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableByteArray ephemeralPublicKey;

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public EcdhKeyExchangeReplyMessage() {
        super(MessageIDConstant.SSH_MSG_KEX_ECDH_REPLY);
    }

    public ModifiableInteger getHostKeyLength() {
        return hostKeyLength;
    }

    public void setHostKeyLength(ModifiableInteger hostKeyLength) {
        this.hostKeyLength = hostKeyLength;
    }

    public void setHostKeyLength(int hostKeyLength) {
        this.hostKeyLength =
                ModifiableVariableFactory.safelySetValue(this.hostKeyLength, hostKeyLength);
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
        this.ephemeralPublicKeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.ephemeralPublicKeyLength, ephemeralPublicKeyLength);
    }

    public ModifiableByteArray getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(ModifiableByteArray ephemeralPublicKey) {
        setEphemeralPublicKey(ephemeralPublicKey, false);
    }

    public void setEphemeralPublicKey(byte[] ephemeralPublicKey) {
        setEphemeralPublicKey(ephemeralPublicKey, false);
    }

    public void setEphemeralPublicKey(
            ModifiableByteArray ephemeralPublicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(ephemeralPublicKey.getValue().length);
        }
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(byte[] ephemeralPublicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(ephemeralPublicKey.length);
        }
        this.ephemeralPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.ephemeralPublicKey, ephemeralPublicKey);
    }

    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int signatureLength) {
        this.signatureLength =
                ModifiableVariableFactory.safelySetValue(this.signatureLength, signatureLength);
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
    public EcdhKeyExchangeReplyMessageHandler getHandler(SshContext context) {
        return new EcdhKeyExchangeReplyMessageHandler(context, this);
    }
}
