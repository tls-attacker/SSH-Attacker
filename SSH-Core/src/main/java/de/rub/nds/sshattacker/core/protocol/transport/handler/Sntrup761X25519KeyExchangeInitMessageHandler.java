/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.Sntrup761X25519KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.Sntrup761X25519KeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.Sntrup761X25519KeyExchangeInitMessagePreperator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.Sntrup761X25519KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class Sntrup761X25519KeyExchangeInitMessageHandler
        extends SshMessageHandler<Sntrup761X25519KeyExchangeInitMessage> {

    public Sntrup761X25519KeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public Sntrup761X25519KeyExchangeInitMessageHandler(
            SshContext context, Sntrup761X25519KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.getChooser().getSntrup761X25591KeyExchange().getKeyAgreement("ec25519")
                .setRemotePublicKey(message.getEphemeralECPublicKey().getValue());
        context.getChooser().getSntrup761X25591KeyExchange().getKeyEncapsulation("sntrup761")
                .setRemotePublicKey(message.getEphemeralSNTRUPPublicKey().getValue());
        context.getExchangeHashInputHolder().setSntrupX25519ClientPublicKey(ArrayConverter.concatenate(
                message.getEphemeralSNTRUPPublicKey().getValue(), message.getEphemeralECPublicKey().getValue()));
    }

    @Override
    public Sntrup761X25519KeyExchangeInitMessageParser getParser(byte[] array) {
        return new Sntrup761X25519KeyExchangeInitMessageParser(array);
    }

    @Override
    public Sntrup761X25519KeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        return new Sntrup761X25519KeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public Sntrup761X25519KeyExchangeInitMessagePreperator getPreparator() {
        return new Sntrup761X25519KeyExchangeInitMessagePreperator(context.getChooser(), message);
    }

    @Override
    public Sntrup761X25519KeyExchangeInitMessageSerializer getSerializer() {
        return new Sntrup761X25519KeyExchangeInitMessageSerializer(message);
    }
}
