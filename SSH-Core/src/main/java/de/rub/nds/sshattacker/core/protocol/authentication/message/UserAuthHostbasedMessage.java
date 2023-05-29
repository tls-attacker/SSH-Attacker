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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthHostbasedMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthHostbasedMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthHostbasedMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthHostbasedMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExchangeHashSignatureMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.HostKeyMessage;
import java.io.InputStream;
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
        this.pubKeyAlgorithm = pubKeyAlgorithm;
        if (adjustLengthField) {
            setPubKeyAlgorithmLength(
                    this.pubKeyAlgorithm.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setPubKeyAlgorithm(String pubKeyAlgorithm, boolean adjustLengthField) {
        this.pubKeyAlgorithm =
                ModifiableVariableFactory.safelySetValue(this.pubKeyAlgorithm, pubKeyAlgorithm);
        if (adjustLengthField) {
            setPubKeyAlgorithmLength(
                    this.pubKeyAlgorithm.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
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
        this.hostName = hostName;
        if (adjustLengthField) {
            setHostNameLength(this.hostName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setHostName(String hostName, boolean adjustLengthField) {
        this.hostName = ModifiableVariableFactory.safelySetValue(this.hostName, hostName);
        if (adjustLengthField) {
            setHostNameLength(this.hostName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
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
        this.clientUserName = clientUserName;
        if (adjustLengthField) {
            setClientUserNameLength(
                    this.clientUserName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setClientUserName(String clientUserName, boolean adjustLengthField) {
        this.clientUserName =
                ModifiableVariableFactory.safelySetValue(this.clientUserName, clientUserName);
        if (adjustLengthField) {
            setClientUserNameLength(
                    this.clientUserName.getValue().getBytes(StandardCharsets.UTF_8).length);
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

    @Override
    public UserAuthHostbasedMessageHandler getHandler(SshContext context) {
        return new UserAuthHostbasedMessageHandler(context);
    }

    @Override
    public UserAuthHostbasedMessageParser getParser(SshContext context, InputStream stream) {
        return new UserAuthHostbasedMessageParser(stream);
    }

    /*
    @Override
    public UserAuthHostbasedMessageParser getParser(byte[] array) {
        return new UserAuthHostbasedMessageParser(array);
    }

    @Override
    public UserAuthHostbasedMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthHostbasedMessageParser(array, startPosition);
    }*/

    @Override
    public UserAuthHostbasedMessagePreparator getPreparator(SshContext context) {
        return new UserAuthHostbasedMessagePreparator(context.getChooser(), this);
    }

    @Override
    public UserAuthHostbasedMessageSerializer getSerializer(SshContext context) {
        return new UserAuthHostbasedMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "AUTH_HOST";
    }
}
