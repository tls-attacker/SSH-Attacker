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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

public class DhGexKeyExchangeInitMessage extends SshMessage<DhGexKeyExchangeInitMessage> {

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableBigInteger ephemeralPublicKey;

    public DhGexKeyExchangeInitMessage() {
        super();
    }

    public DhGexKeyExchangeInitMessage(DhGexKeyExchangeInitMessage other) {
        super(other);
        ephemeralPublicKeyLength =
                other.ephemeralPublicKeyLength != null
                        ? other.ephemeralPublicKeyLength.createCopy()
                        : null;
        ephemeralPublicKey =
                other.ephemeralPublicKey != null ? other.ephemeralPublicKey.createCopy() : null;
    }

    @Override
    public DhGexKeyExchangeInitMessage createCopy() {
        return new DhGexKeyExchangeInitMessage(this);
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
    public DhGexKeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeInitMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        DhGexKeyExchangeInitMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
