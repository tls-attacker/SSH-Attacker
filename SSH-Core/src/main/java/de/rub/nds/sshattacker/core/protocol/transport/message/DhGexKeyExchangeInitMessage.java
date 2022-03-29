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
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;

public class DhGexKeyExchangeInitMessage extends SshMessage<DhGexKeyExchangeInitMessage> {
    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableBigInteger ephemeralPublicKey;

    public DhGexKeyExchangeInitMessage() {
        super(MessageIdConstant.SSH_MSG_KEX_DH_GEX_INIT);
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
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(ephemeralPublicKey.getValue().toByteArray().length);
        }
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(BigInteger ephemeralPublicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEphemeralPublicKeyLength(ephemeralPublicKey.toByteArray().length);
        }
        this.ephemeralPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.ephemeralPublicKey, ephemeralPublicKey);
    }

    @Override
    public DhGexKeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeInitMessageHandler(context, this);
    }
}
