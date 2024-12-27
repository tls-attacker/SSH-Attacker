/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeInitMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeInitMessage> {

    public DhGexKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public DhGexKeyExchangeInitMessageHandler(
            SshContext context, DhGexKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.getChooser()
                .getDhGexKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setDhGexClientPublicKey(message.getEphemeralPublicKey().getValue());
    }

    @Override
    public DhGexKeyExchangeInitMessageParser getParser(byte[] array) {
        return new DhGexKeyExchangeInitMessageParser(array);
    }

    @Override
    public DhGexKeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        return new DhGexKeyExchangeInitMessageParser(array, startPosition);
    }

    public static final DhGexKeyExchangeInitMessagePreparator PREPARATOR =
            new DhGexKeyExchangeInitMessagePreparator();

    public static final DhGexKeyExchangeInitMessageSerializer SERIALIZER =
            new DhGexKeyExchangeInitMessageSerializer();
}
