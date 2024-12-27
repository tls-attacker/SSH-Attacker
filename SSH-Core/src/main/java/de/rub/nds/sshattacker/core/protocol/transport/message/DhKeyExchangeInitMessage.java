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
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

public class DhKeyExchangeInitMessage extends SshMessage<DhKeyExchangeInitMessage> {

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableBigInteger ephemeralPublicKey;

    public DhKeyExchangeInitMessage() {
        super();
    }

    public DhKeyExchangeInitMessage(DhKeyExchangeInitMessage other) {
        super(other);
        ephemeralPublicKeyLength =
                other.ephemeralPublicKeyLength != null
                        ? other.ephemeralPublicKeyLength.createCopy()
                        : null;
        ephemeralPublicKey =
                other.ephemeralPublicKey != null ? other.ephemeralPublicKey.createCopy() : null;
    }

    @Override
    public DhKeyExchangeInitMessage createCopy() {
        return new DhKeyExchangeInitMessage(this);
    }

    public ModifiableInteger getEphemeralPublicKeyLength() {
        return ephemeralPublicKeyLength;
    }

    public void setEphemeralPublicKeyLength(ModifiableInteger ephemeralPublicKeyLength) {
        this.ephemeralPublicKeyLength = ephemeralPublicKeyLength;
    }

    public void setEphemeralPublicKeyLength(int publicKeyLength) {
        ephemeralPublicKeyLength =
                ModifiableVariableFactory.safelySetValue(ephemeralPublicKeyLength, publicKeyLength);
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
    public DhKeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new DhKeyExchangeInitMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        DhKeyExchangeInitMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
