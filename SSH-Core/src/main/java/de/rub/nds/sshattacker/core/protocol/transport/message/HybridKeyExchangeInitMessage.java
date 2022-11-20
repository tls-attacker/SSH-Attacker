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
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.Sntrup761X25519KeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class HybridKeyExchangeInitMessage
        extends SshMessage<HybridKeyExchangeInitMessage> {

    private ModifiableInteger ephemeralECPublicKeyLength;
    private ModifiableByteArray ephemeralECPublicKey;
    private ModifiableInteger ephemeralSNTRUPPublicKeyLength;
    private ModifiableByteArray ephemeralSNTRUPPublicKey;

    public ModifiableInteger getEphemeralECPublicKeyLength() {
        return ephemeralECPublicKeyLength;
    }

    public void setEphemeralECPublicKeyLength(ModifiableInteger ephemeralECPublicKeyLength) {
        this.ephemeralECPublicKeyLength = ephemeralECPublicKeyLength;
    }

    public void setEphemeralECPublicKeyLength(int ephemeralECPublicKeyLength) {
        this.ephemeralECPublicKeyLength = ModifiableVariableFactory.safelySetValue(
                this.ephemeralECPublicKeyLength, ephemeralECPublicKeyLength);
    }

    public ModifiableByteArray getEphemeralECPublicKey() {
        return ephemeralECPublicKey;
    }

    public void setEphemeralECPublicKey(ModifiableByteArray ephemeralECPublicKey) {
        setEphemeralECPublicKey(ephemeralECPublicKey, false);
    }

    public void setEphemeralECPublicKey(byte[] ephemeralECPublicKey) {
        setEphemeralECPublicKey(ephemeralECPublicKey, false);
    }

    public void setEphemeralECPublicKey(
            ModifiableByteArray ephemeralECPublicKey, boolean adjustLengthField) {
        this.ephemeralECPublicKey = ephemeralECPublicKey;
        if (adjustLengthField) {
            setEphemeralECPublicKeyLength(ephemeralECPublicKey.getValue().length);
        }

    }

    public void setEphemeralECPublicKey(byte[] ephemeralECPublicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEphemeralECPublicKeyLength(ephemeralECPublicKey.length);
        }
        this.ephemeralECPublicKey = ModifiableVariableFactory.safelySetValue(
                this.ephemeralECPublicKey, ephemeralECPublicKey);
    }

    public ModifiableInteger getEphemeralSNTRUPPublicKeyLength() {
        return ephemeralSNTRUPPublicKeyLength;
    }

    public void setEphemeralSNTRUPPublicKeyLength(
            ModifiableInteger ephemeralSNTRUPPublicKeyLength) {
        this.ephemeralSNTRUPPublicKeyLength = ephemeralSNTRUPPublicKeyLength;
    }

    public void setEphemeralSNTRUPPublicKeyLength(int ephemeralSNTRUPPublicKeyLength) {
        this.ephemeralSNTRUPPublicKeyLength = ModifiableVariableFactory.safelySetValue(
                this.ephemeralSNTRUPPublicKeyLength, ephemeralSNTRUPPublicKeyLength);
    }

    public ModifiableByteArray getEphemeralSNTRUPPublicKey() {
        return ephemeralSNTRUPPublicKey;
    }

    public void setEphemeralSNTRUPPublicKey(ModifiableByteArray ephemeralSNTRUPPublicKey) {
        setEphemeralSNTRUPPublicKey(ephemeralSNTRUPPublicKey, false);
    }

    public void setEphemeralSNTRUPPublicKey(byte[] ephemeralSNTRUPPublicKey) {
        setEphemeralSNTRUPPublicKey(ephemeralSNTRUPPublicKey, false);
    }

    public void setEphemeralSNTRUPPublicKey(
            ModifiableByteArray ephemeralSNTRUPPublicKey, boolean adjustLengthField) {
        this.ephemeralSNTRUPPublicKey = ephemeralSNTRUPPublicKey;
        if (adjustLengthField) {
            setEphemeralSNTRUPPublicKeyLength(ephemeralSNTRUPPublicKey.getValue().length);
        }
    }

    public void setEphemeralSNTRUPPublicKey(
            byte[] ephemeralSNTRUPPublicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEphemeralSNTRUPPublicKeyLength(ephemeralSNTRUPPublicKey.length);
        }
        this.ephemeralSNTRUPPublicKey = ModifiableVariableFactory.safelySetValue(
                this.ephemeralSNTRUPPublicKey, ephemeralSNTRUPPublicKey);
    }

    @Override
    public SshMessageHandler<HybridKeyExchangeInitMessage> getHandler(SshContext context) {
        return new Sntrup761X25519KeyExchangeInitMessageHandler(context, this);
    }
}
