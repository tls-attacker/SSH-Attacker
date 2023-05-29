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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeInitMessageSerializer;
import java.io.InputStream;
import java.math.BigInteger;

public class DhGexKeyExchangeInitMessage extends SshMessage<DhGexKeyExchangeInitMessage> {

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableBigInteger ephemeralPublicKey;

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

    @Override
    public DhGexKeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeInitMessageHandler(context);
    }

    @Override
    public SshMessageParser<DhGexKeyExchangeInitMessage> getParser(
            SshContext context, InputStream stream) {
        return new DhGexKeyExchangeInitMessageParser(stream);
    }

    @Override
    public DhGexKeyExchangeInitMessagePreparator getPreparator(SshContext context) {
        return new DhGexKeyExchangeInitMessagePreparator(context.getChooser(), this);
    }

    @Override
    public DhGexKeyExchangeInitMessageSerializer getSerializer(SshContext context) {
        return new DhGexKeyExchangeInitMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "DHGexKeyExInit";
    }
}
