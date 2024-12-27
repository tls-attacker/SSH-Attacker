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
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.EcdhKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class EcdhKeyExchangeInitMessage extends SshMessage<EcdhKeyExchangeInitMessage> {

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableByteArray ephemeralPublicKey;

    public EcdhKeyExchangeInitMessage() {
        super();
    }

    public EcdhKeyExchangeInitMessage(EcdhKeyExchangeInitMessage other) {
        super(other);
        ephemeralPublicKeyLength =
                other.ephemeralPublicKeyLength != null
                        ? other.ephemeralPublicKeyLength.createCopy()
                        : null;
        ephemeralPublicKey =
                other.ephemeralPublicKey != null ? other.ephemeralPublicKey.createCopy() : null;
    }

    @Override
    public EcdhKeyExchangeInitMessage createCopy() {
        return new EcdhKeyExchangeInitMessage(this);
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
        this.ephemeralPublicKey = ephemeralPublicKey;
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(this.ephemeralPublicKey.getValue().length);
        }
    }

    public void setEphemeralPublicKey(byte[] ephemeralPublicKey, boolean adjustLengthField) {
        this.ephemeralPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.ephemeralPublicKey, ephemeralPublicKey);
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(this.ephemeralPublicKey.getValue().length);
        }
    }

    public void setSoftlyEphemeralPublicKey(
            byte[] ephemeralPublicKey, boolean adjustLengthField, Config config) {
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
                setEphemeralPublicKeyLength(this.ephemeralPublicKey.getValue().length);
            }
        }
    }

    @Override
    public EcdhKeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new EcdhKeyExchangeInitMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        EcdhKeyExchangeInitMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return EcdhKeyExchangeInitMessageHandler.SERIALIZER.serialize(this);
    }
}
