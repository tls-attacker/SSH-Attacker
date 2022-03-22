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
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangePubkeyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class RsaKeyExchangePubkeyMessage extends SshMessage<RsaKeyExchangePubkeyMessage> {

    private ModifiableInteger hostKeyLength;
    private ModifiableByteArray hostKey;

    private ModifiableInteger transientPublicKeyLength;
    private ModifiableByteArray transientPublicKey;

    public RsaKeyExchangePubkeyMessage() {
        super(MessageIDConstant.SSH_MSG_KEXRSA_PUBKEY);
    }

    // Host Key (K_S) Methods
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

    public void setHostKey(byte[] hostKey) {
        setHostKey(hostKey, false);
    }

    public void setHostKey(ModifiableByteArray hostkey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setHostKeyLength(hostkey.getValue().length);
        }
        this.hostKey = hostkey;
    }

    public void setHostKey(byte[] hostKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setHostKeyLength(hostKey.length);
        }
        this.hostKey = ModifiableVariableFactory.safelySetValue(this.hostKey, hostKey);
    }

    // Transient Public Key (K_T) Methods
    public ModifiableInteger getTransientPublicKeyLength() {
        return transientPublicKeyLength;
    }

    public void setTransientPublicKeyLength(ModifiableInteger transientPublicKeyLength) {
        this.transientPublicKeyLength = transientPublicKeyLength;
    }

    public void setTransientPublicKeyLength(int transientPublicKeyLength) {
        this.transientPublicKeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.transientPublicKeyLength, transientPublicKeyLength);
    }

    public ModifiableByteArray getTransientPublicKey() {
        return transientPublicKey;
    }

    public void setTransientPublicKey(byte[] transientPublicKey) {
        setTransientPublicKey(transientPublicKey, false);
    }

    public void setTransientPublicKey(
            ModifiableByteArray transientPublicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTransientPublicKeyLength(transientPublicKey.getValue().length);
        }
        this.transientPublicKey = transientPublicKey;
    }

    public void setTransientPublicKey(byte[] transientPublicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTransientPublicKeyLength(transientPublicKey.length);
        }
        this.transientPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.transientPublicKey, transientPublicKey);
    }

    @SuppressWarnings("unchecked")
    public SshPublicKey<RSAPublicKey, ?> getPublicKey() {
        // Parse just-in-time to allow for modifications to the transient public key to take effect
        return (SshPublicKey<RSAPublicKey, ?>)
                PublicKeyHelper.parse(PublicKeyFormat.SSH_RSA, this.transientPublicKey.getValue());
    }

    public BigInteger getModulus() {
        return ((RSAPublicKey) getPublicKey().getPublicKey()).getModulus();
    }

    public BigInteger getPublicExponent() {
        return ((RSAPublicKey) getPublicKey().getPublicKey()).getPublicExponent();
    }

    @Override
    public SshMessageHandler<RsaKeyExchangePubkeyMessage> getHandler(SshContext context) {
        return new RsaKeyExchangePubkeyMessageHandler(context, this);
    }
}
