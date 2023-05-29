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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.EcdhKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.EcdhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.EcdhKeyExchangeInitMessageSerializer;
import java.io.InputStream;

public class EcdhKeyExchangeInitMessage extends SshMessage<EcdhKeyExchangeInitMessage> {

    private ModifiableInteger ephemeralPublicKeyLength;
    private ModifiableByteArray ephemeralPublicKey;

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

    @Override
    public EcdhKeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new EcdhKeyExchangeInitMessageHandler(context);
    }

    @Override
    public EcdhKeyExchangeInitMessageParser getParser(SshContext context, InputStream stream) {
        return new EcdhKeyExchangeInitMessageParser(stream);
    }

    @Override
    public EcdhKeyExchangeInitMessagePreparator getPreparator(SshContext context) {
        return new EcdhKeyExchangeInitMessagePreparator(context.getChooser(), this);
    }

    @Override
    public EcdhKeyExchangeInitMessageSerializer getSerializer(SshContext context) {
        return new EcdhKeyExchangeInitMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "ECDHE_KEX_INIT";
    }
}
