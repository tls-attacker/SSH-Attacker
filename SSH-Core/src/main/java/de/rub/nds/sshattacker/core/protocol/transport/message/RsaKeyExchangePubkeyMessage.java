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
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangePubkeyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class RsaKeyExchangePubkeyMessage extends SshMessage<RsaKeyExchangePubkeyMessage>
        implements HostKeyMessage {

    private ModifiableInteger hostKeyBytesLength;
    private ModifiableByteArray hostKeyBytes;

    private ModifiableInteger transientPublicKeyBytesLength;
    private ModifiableByteArray transientPublicKeyBytes;

    public RsaKeyExchangePubkeyMessage() {
        super(MessageIDConstant.SSH_MSG_KEXRSA_PUBKEY);
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
        this.setHostKeyBytes(hostKeyBytes, false);
    }

    @Override
    public void setHostKeyBytes(byte[] hostKeyBytes) {
        this.setHostKeyBytes(hostKeyBytes, false);
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
                PublicKeyHelper.parse(
                        PublicKeyFormat.SSH_RSA, this.transientPublicKeyBytes.getValue());
    }

    public void setTransientPublicKeyBytes(ModifiableByteArray transientPublicKeyBytes) {
        this.setTransientPublicKeyBytes(transientPublicKeyBytes, false);
    }

    public void setTransientPublicKeyBytes(byte[] transientPublicKeyBytes) {
        this.setTransientPublicKeyBytes(transientPublicKeyBytes, false);
    }

    public void setTransientPublicKeyBytes(
            ModifiableByteArray transientPublicKeyBytes, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTransientPublicKeyBytesLength(transientPublicKeyBytes.getValue().length);
        }
        this.transientPublicKeyBytes = transientPublicKeyBytes;
    }

    public void setTransientPublicKeyBytes(
            byte[] transientPublicKeyBytes, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTransientPublicKeyBytesLength(transientPublicKeyBytes.length);
        }
        this.transientPublicKeyBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.transientPublicKeyBytes, transientPublicKeyBytes);
    }

    public BigInteger getModulus() {
        return ((RSAPublicKey) getTransientPublicKey().getPublicKey()).getModulus();
    }

    public BigInteger getPublicExponent() {
        return ((RSAPublicKey) getTransientPublicKey().getPublicKey()).getPublicExponent();
    }

    @Override
    public SshMessageHandler<RsaKeyExchangePubkeyMessage> getHandler(SshContext context) {
        return new RsaKeyExchangePubkeyMessageHandler(context, this);
    }
}
