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
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhKeyExchangeInitMessageSerializer;
import java.io.InputStream;
import java.math.BigInteger;

public class DhKeyExchangeInitMessage extends SshMessage<DhKeyExchangeInitMessage> {

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableBigInteger ephemeralPublicKey;

    public ModifiableInteger getEphemeralPublicKeyLength() {
        return ephemeralPublicKeyLength;
    }

    public void setEphemeralPublicKeyLength(ModifiableInteger ephemeralPublicKeyLength) {
        this.ephemeralPublicKeyLength = ephemeralPublicKeyLength;
    }

    public void setEphemeralPublicKeyLength(int publicKeyLength) {
        this.ephemeralPublicKeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.ephemeralPublicKeyLength, publicKeyLength);
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
    public DhKeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new DhKeyExchangeInitMessageHandler(context);
    }

    @Override
    public SshMessageParser<DhKeyExchangeInitMessage> getParser(
            SshContext context, InputStream stream) {
        return new DhKeyExchangeInitMessageParser(stream);
    }

    @Override
    public DhKeyExchangeInitMessagePreparator getPreparator(SshContext context) {
        return new DhKeyExchangeInitMessagePreparator(context.getChooser(), this);
    }

    @Override
    public DhKeyExchangeInitMessageSerializer getSerializer(SshContext context) {
        return new DhKeyExchangeInitMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "DHgKexInit";
    }
}
