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
import de.rub.nds.sshattacker.core.config.Config;
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

    public UserAuthHostbasedMessage() {
        super();
    }

    public UserAuthHostbasedMessage(UserAuthHostbasedMessage other) {
        super(other);
        pubKeyAlgorithmLength =
                other.pubKeyAlgorithmLength != null
                        ? other.pubKeyAlgorithmLength.createCopy()
                        : null;
        pubKeyAlgorithm = other.pubKeyAlgorithm != null ? other.pubKeyAlgorithm.createCopy() : null;
        hostKeyBytesLength =
                other.hostKeyBytesLength != null ? other.hostKeyBytesLength.createCopy() : null;
        hostKeyBytes = other.hostKeyBytes != null ? other.hostKeyBytes.createCopy() : null;
        hostNameLength = other.hostNameLength != null ? other.hostNameLength.createCopy() : null;
        hostName = other.hostName != null ? other.hostName.createCopy() : null;
        clientUserNameLength =
                other.clientUserNameLength != null ? other.clientUserNameLength.createCopy() : null;
        clientUserName = other.clientUserName != null ? other.clientUserName.createCopy() : null;
        signatureLength = other.signatureLength != null ? other.signatureLength.createCopy() : null;
        signature = other.signature != null ? other.signature.createCopy() : null;
    }

    @Override
    public UserAuthHostbasedMessage createCopy() {
        return new UserAuthHostbasedMessage(this);
    }

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

    public void setSoftlyPubKeyAlgorithm(
            String pubKeyAlgorithm, boolean adjustLengthField, Config config) {
        if (this.pubKeyAlgorithm == null || this.pubKeyAlgorithm.getOriginalValue() == null) {
            this.pubKeyAlgorithm =
                    ModifiableVariableFactory.safelySetValue(this.pubKeyAlgorithm, pubKeyAlgorithm);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || pubKeyAlgorithmLength == null
                    || pubKeyAlgorithmLength.getOriginalValue() == null) {
                setPubKeyAlgorithmLength(
                        this.pubKeyAlgorithm.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
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

    public void setSoftlyHostKeyBytes(
            byte[] hostKeyBytes, boolean adjustLengthField, Config config) {
        if (this.hostKeyBytes == null || this.hostKeyBytes.getOriginalValue() == null) {
            this.hostKeyBytes =
                    ModifiableVariableFactory.safelySetValue(this.hostKeyBytes, hostKeyBytes);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || hostKeyBytesLength == null
                    || hostKeyBytesLength.getOriginalValue() == null) {
                setHostKeyBytesLength(this.hostKeyBytes.getValue().length);
            }
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

    public void setSoftlyHostName(String hostName, boolean adjustLengthField, Config config) {
        if (this.hostName == null || this.hostName.getOriginalValue() == null) {
            this.hostName = ModifiableVariableFactory.safelySetValue(this.hostName, hostName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || hostNameLength == null
                    || hostNameLength.getOriginalValue() == null) {
                setHostNameLength(this.hostName.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
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

    public void setSoftlyClientUserName(
            String clientUserName, boolean adjustLengthField, Config config) {
        if (this.clientUserName == null || this.clientUserName.getOriginalValue() == null) {
            this.clientUserName =
                    ModifiableVariableFactory.safelySetValue(this.clientUserName, clientUserName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || clientUserNameLength == null
                    || clientUserNameLength.getOriginalValue() == null) {
                setClientUserNameLength(
                        this.clientUserName.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
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

    public void setSoftlySignature(byte[] signature, boolean adjustLengthField, Config config) {
        if (this.signature == null || this.signature.getOriginalValue() == null) {
            this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || signatureLength == null
                    || signatureLength.getOriginalValue() == null) {
                setSignatureLength(this.signature.getValue().length);
            }
        }
    }

    @Override
    public UserAuthHostbasedMessageHandler getHandler(SshContext context) {
        return new UserAuthHostbasedMessageHandler(context, this);
    }
}
