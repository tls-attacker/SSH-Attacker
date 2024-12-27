/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeReplyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

public class DhGexKeyExchangeReplyMessage extends SshMessage<DhGexKeyExchangeReplyMessage>
        implements HostKeyMessage, ExchangeHashSignatureMessage {

    private ModifiableInteger hostKeyBytesLength;
    private ModifiableByteArray hostKeyBytes;

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableBigInteger ephemeralPublicKey;

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public DhGexKeyExchangeReplyMessage() {
        super();
    }

    public DhGexKeyExchangeReplyMessage(DhGexKeyExchangeReplyMessage other) {
        super(other);
        hostKeyBytesLength =
                other.hostKeyBytesLength != null ? other.hostKeyBytesLength.createCopy() : null;
        hostKeyBytes = other.hostKeyBytes != null ? other.hostKeyBytes.createCopy() : null;
        ephemeralPublicKeyLength =
                other.ephemeralPublicKeyLength != null
                        ? other.ephemeralPublicKeyLength.createCopy()
                        : null;
        ephemeralPublicKey =
                other.ephemeralPublicKey != null ? other.ephemeralPublicKey.createCopy() : null;
        signatureLength = other.signatureLength != null ? other.signatureLength.createCopy() : null;
        signature = other.signature != null ? other.signature.createCopy() : null;
    }

    @Override
    public DhGexKeyExchangeReplyMessage createCopy() {
        return new DhGexKeyExchangeReplyMessage(this);
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
        if (config.getAlwaysPrepareKex()
                || this.hostKeyBytes == null
                || this.hostKeyBytes.getOriginalValue() == null) {
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

    public ModifiableBigInteger getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(ModifiableBigInteger ephemeralPublicKey) {
        setEphemeralPublicKey(ephemeralPublicKey, false);
    }

    public void setEphemeralPublicKey(BigInteger ephemeralPublicKey) {
        setEphemeralPublicKey(ephemeralPublicKey, false);
    }

    public void setEphemeralPublicKey(
            ModifiableBigInteger ephemeralPublicKey, boolean adjustLengthField) {
        this.ephemeralPublicKey = ephemeralPublicKey;
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(this.ephemeralPublicKey.getValue().toByteArray().length);
        }
    }

    public void setEphemeralPublicKey(BigInteger ephemeralPublicKey, boolean adjustLengthField) {
        this.ephemeralPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.ephemeralPublicKey, ephemeralPublicKey);
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(this.ephemeralPublicKey.getValue().toByteArray().length);
        }
    }

    public void setSoftlyEphemeralPublicKey(
            BigInteger ephemeralPublicKey, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.ephemeralPublicKey == null
                || this.ephemeralPublicKey.getOriginalValue() == null) {
            this.ephemeralPublicKey =
                    ModifiableVariableFactory.safelySetValue(
                            this.ephemeralPublicKey, ephemeralPublicKey);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || ephemeralPublicKeyLength == null
                    || ephemeralPublicKeyLength.getOriginalValue() == null) {
                setEphemeralPublicKeyLength(
                        this.ephemeralPublicKey.getValue().toByteArray().length);
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
        if (config.getAlwaysPrepareKex()
                || this.signature == null
                || this.signature.getOriginalValue() == null) {
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
    public DhGexKeyExchangeReplyMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeReplyMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        DhGexKeyExchangeReplyMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
