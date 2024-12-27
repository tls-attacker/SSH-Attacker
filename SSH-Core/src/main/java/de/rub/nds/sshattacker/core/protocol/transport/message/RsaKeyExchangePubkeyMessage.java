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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangePubkeyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

public class RsaKeyExchangePubkeyMessage extends SshMessage<RsaKeyExchangePubkeyMessage>
        implements HostKeyMessage {

    private ModifiableInteger hostKeyBytesLength;
    private ModifiableByteArray hostKeyBytes;

    private ModifiableInteger transientPublicKeyBytesLength;
    private ModifiableByteArray transientPublicKeyBytes;

    public RsaKeyExchangePubkeyMessage() {
        super();
    }

    public RsaKeyExchangePubkeyMessage(RsaKeyExchangePubkeyMessage other) {
        super(other);
        hostKeyBytesLength =
                other.hostKeyBytesLength != null ? other.hostKeyBytesLength.createCopy() : null;
        hostKeyBytes = other.hostKeyBytes != null ? other.hostKeyBytes.createCopy() : null;
        transientPublicKeyBytesLength =
                other.transientPublicKeyBytesLength != null
                        ? other.transientPublicKeyBytesLength.createCopy()
                        : null;
        transientPublicKeyBytes =
                other.transientPublicKeyBytes != null
                        ? other.transientPublicKeyBytes.createCopy()
                        : null;
    }

    @Override
    public RsaKeyExchangePubkeyMessage createCopy() {
        return new RsaKeyExchangePubkeyMessage(this);
    }

    // Host Key (K_S) Methods
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

    // Transient Public Key (K_T) Methods
    public ModifiableInteger getTransientPublicKeyBytesLength() {
        return transientPublicKeyBytesLength;
    }

    public void setTransientPublicKeyBytesLength(ModifiableInteger transientPublicKeyBytesLength) {
        this.transientPublicKeyBytesLength = transientPublicKeyBytesLength;
    }

    public void setTransientPublicKeyBytesLength(int transientPublicKeyBytesLength) {
        this.transientPublicKeyBytesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.transientPublicKeyBytesLength, transientPublicKeyBytesLength);
    }

    public ModifiableByteArray getTransientPublicKeyBytes() {
        return transientPublicKeyBytes;
    }

    @SuppressWarnings("unchecked")
    public SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> getTransientPublicKey() {
        return (SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey>)
                PublicKeyHelper.parse(PublicKeyFormat.SSH_RSA, transientPublicKeyBytes.getValue());
    }

    public void setTransientPublicKeyBytes(ModifiableByteArray transientPublicKeyBytes) {
        setTransientPublicKeyBytes(transientPublicKeyBytes, false);
    }

    public void setTransientPublicKeyBytes(byte[] transientPublicKeyBytes) {
        setTransientPublicKeyBytes(transientPublicKeyBytes, false);
    }

    public void setTransientPublicKeyBytes(
            ModifiableByteArray transientPublicKeyBytes, boolean adjustLengthField) {
        this.transientPublicKeyBytes = transientPublicKeyBytes;
        if (adjustLengthField) {
            setTransientPublicKeyBytesLength(this.transientPublicKeyBytes.getValue().length);
        }
    }

    public void setTransientPublicKeyBytes(
            byte[] transientPublicKeyBytes, boolean adjustLengthField) {
        this.transientPublicKeyBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.transientPublicKeyBytes, transientPublicKeyBytes);
        if (adjustLengthField) {
            setTransientPublicKeyBytesLength(this.transientPublicKeyBytes.getValue().length);
        }
    }

    public void setSoftlyTransientPublicKeyBytes(
            byte[] transientPublicKeyBytes, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.transientPublicKeyBytes == null
                || this.transientPublicKeyBytes.getOriginalValue() == null) {
            this.transientPublicKeyBytes =
                    ModifiableVariableFactory.safelySetValue(
                            this.transientPublicKeyBytes, transientPublicKeyBytes);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || transientPublicKeyBytesLength == null
                    || transientPublicKeyBytesLength.getOriginalValue() == null) {
                setTransientPublicKeyBytesLength(this.transientPublicKeyBytes.getValue().length);
            }
        }
    }

    public BigInteger getModulus() {
        return getTransientPublicKey().getPublicKey().getModulus();
    }

    public BigInteger getPublicExponent() {
        return getTransientPublicKey().getPublicKey().getPublicExponent();
    }

    @Override
    public RsaKeyExchangePubkeyMessageHandler getHandler(SshContext context) {
        return new RsaKeyExchangePubkeyMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        RsaKeyExchangePubkeyMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return RsaKeyExchangePubkeyMessageHandler.SERIALIZER.serialize(this);
    }
}
