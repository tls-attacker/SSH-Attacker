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
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangePubkeyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.RsaPublicKey;
import de.rub.nds.sshattacker.core.util.RsaPublicKeyParser;
import java.util.List;

public class RsaKeyExchangePubkeyMessage extends SshMessage<RsaKeyExchangePubkeyMessage> {

    private ModifiableInteger hostKeyLength;
    private ModifiableByteArray hostKey;

    private ModifiableInteger transientPubkeyLength;
    private ModifiableByteArray transientPubkey;

    private RsaPublicKey publicKey;

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
    public ModifiableInteger getTransientPubkeyLength() {
        return transientPubkeyLength;
    }

    public void setTransientPubkeyLength(ModifiableInteger transientPubkeyLength) {
        this.transientPubkeyLength = transientPubkeyLength;
    }

    public void setTransientPubkeyLength(int transientPubkeyLength) {
        this.transientPubkeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.transientPubkeyLength, transientPubkeyLength);
    }

    public ModifiableByteArray getTransientPubkey() {
        return transientPubkey;
    }

    public void setTransientPubkey(byte[] transientPubkey) {
        setTransientPubkey(transientPubkey, false);
    }

    public void setTransientPubkey(ModifiableByteArray transientPubkey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTransientPubkeyLength(transientPubkey.getValue().length);
        }
        this.transientPubkey = transientPubkey;
        parsePublicKey();
    }

    public void setTransientPubkey(byte[] transientPubkey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTransientPubkeyLength(transientPubkey.length);
        }
        this.transientPubkey =
                ModifiableVariableFactory.safelySetValue(this.transientPubkey, transientPubkey);
        parsePublicKey();
    }

    private void parsePublicKey() {
        RsaPublicKeyParser parser = new RsaPublicKeyParser(this.transientPubkey.getValue(), 0);
        this.publicKey = parser.parse();
    }

    public ModifiableBigInteger getExponent() {
        return this.publicKey.getExponent();
    }

    public ModifiableBigInteger getModulus() {
        return this.publicKey.getModulus();
    }

    @Override
    public SshMessageHandler<RsaKeyExchangePubkeyMessage> getHandler(SshContext context) {
        return new RsaKeyExchangePubkeyMessageHandler(context, this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        holders.add(publicKey);
        return holders;
    }
}
