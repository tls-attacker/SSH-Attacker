/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthHostbasedMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExchangeHashSignatureMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.HostKeyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class UserAuthHostbasedMessage extends UserAuthRequestMessage<UserAuthHostbasedMessage>
        implements HostKeyMessage, ExchangeHashSignatureMessage {

    private ModifiableInteger pubKeyAlgorithmLength;
    private ModifiableString pubKeyAlgorithm;
    private ModifiableInteger hostKeyBytesLength;
    private ModifiableByteArray hostKeyBytes;
    private ModifiableInteger hostNameLength;
    private ModifiableString hostName;
    private ModifiableInteger clientUserNameLength;
    private ModifiableString clientUserName;
    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public ModifiableInteger getPubKeyAlgorithmLength() {
        return pubKeyAlgorithmLength;
    }

    public void setPubKeyAlgorithmLength(ModifiableInteger pubKeyAlgorithmLength) {
        this.pubKeyAlgorithmLength = pubKeyAlgorithmLength;
    }

    public void setPubKeyAlgorithmLength(int pubKeyAlgorithmLength) {
        this.pubKeyAlgorithmLength =
                ModifiableVariableFactory.safelySetValue(
                        this.pubKeyAlgorithmLength, pubKeyAlgorithmLength);
    }

    public ModifiableString getPubKeyAlgorithm() {
        return pubKeyAlgorithm;
    }

    public void setPubKeyAlgorithm(ModifiableString pubKeyAlgorithm) {
        this.pubKeyAlgorithm = pubKeyAlgorithm;
    }

    public void setPubKeyAlgorithm(String pubKeyAlgorithm) {
        this.pubKeyAlgorithm =
                ModifiableVariableFactory.safelySetValue(this.pubKeyAlgorithm, pubKeyAlgorithm);
    }

    public void setPubKeyAlgorithm(ModifiableString pubKeyAlgorithm, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPubKeyAlgorithmLength(
                    pubKeyAlgorithm.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.pubKeyAlgorithm = pubKeyAlgorithm;
    }

    public void setPubKeyAlgorithm(String pubKeyAlgorithm, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPubKeyAlgorithmLength(pubKeyAlgorithm.getBytes(StandardCharsets.UTF_8).length);
        }
        this.pubKeyAlgorithm =
                ModifiableVariableFactory.safelySetValue(this.pubKeyAlgorithm, pubKeyAlgorithm);
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
        if (adjustLengthField) {
            setHostKeyBytesLength(hostKeyBytes.getValue().length);
        }
        this.hostKeyBytes = hostKeyBytes;
    }

    @Override
    public void setHostKeyBytes(byte[] hostKeyBytes, boolean adjustLengthField) {
        if (adjustLengthField) {
            setHostKeyBytesLength(hostKeyBytes.length);
        }
        this.hostKeyBytes =
                ModifiableVariableFactory.safelySetValue(this.hostKeyBytes, hostKeyBytes);
    }

    public ModifiableInteger getHostNameLength() {
        return hostNameLength;
    }

    public void setHostNameLength(ModifiableInteger hostNameLength) {
        this.hostNameLength = hostNameLength;
    }

    public void setHostNameLength(int hostNameLength) {
        this.hostNameLength =
                ModifiableVariableFactory.safelySetValue(this.hostNameLength, hostNameLength);
    }

    public ModifiableString getHostName() {
        return hostName;
    }

    public void setHostName(ModifiableString hostName) {
        this.hostName = hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = ModifiableVariableFactory.safelySetValue(this.hostName, hostName);
    }

    public void setHostName(ModifiableString hostName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setHostNameLength(hostName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.hostName = hostName;
    }

    public void setHostName(String hostName, boolean adjusLengthField) {
        if (adjusLengthField) {
            setHostNameLength(hostName.getBytes(StandardCharsets.UTF_8).length);
        }
        this.hostName = ModifiableVariableFactory.safelySetValue(this.hostName, hostName);
    }

    public ModifiableInteger getClientUserNameLength() {
        return clientUserNameLength;
    }

    public void setClientUserNameLength(ModifiableInteger clientUserNameLength) {
        this.clientUserNameLength = clientUserNameLength;
    }

    public void setClientUserNameLength(int clientUserNameLength) {
        this.clientUserNameLength =
                ModifiableVariableFactory.safelySetValue(
                        this.clientUserNameLength, clientUserNameLength);
    }

    public ModifiableString getClientUserName() {
        return clientUserName;
    }

    public void setClientUserName(ModifiableString clientUserName) {
        this.clientUserName = clientUserName;
    }

    public void setClientUserName(String clientUserName) {
        this.clientUserName =
                ModifiableVariableFactory.safelySetValue(this.clientUserName, clientUserName);
    }

    public void setClientUserName(ModifiableString clientUserName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setClientUserNameLength(
                    clientUserName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.clientUserName = clientUserName;
    }

    public void setClientUserName(String clientUserName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setClientUserNameLength(clientUserName.getBytes(StandardCharsets.UTF_8).length);
        }
        this.clientUserName =
                ModifiableVariableFactory.safelySetValue(this.clientUserName, clientUserName);
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
    public UserAuthHostbasedMessageHandler getHandler(SshContext context) {
        return new UserAuthHostbasedMessageHandler(context, this);
    }
}
