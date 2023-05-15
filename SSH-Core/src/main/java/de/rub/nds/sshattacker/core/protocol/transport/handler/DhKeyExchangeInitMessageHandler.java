/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhKeyExchangeInitMessageHandler extends SshMessageHandler<DhKeyExchangeInitMessage> {

    public DhKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public DhKeyExchangeInitMessageHandler(SshContext context, DhKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.getChooser()
                .getDhKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setDhClientPublicKey(message.getEphemeralPublicKey().getValue());
    }

    @Override
    public SshMessageParser<DhKeyExchangeInitMessage> getParser(byte[] array) {
        return new DhKeyExchangeInitMessageParser(array);
    }

    @Override
    public SshMessageParser<DhKeyExchangeInitMessage> getParser(byte[] array, int startPosition) {
        return new DhKeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public DhKeyExchangeInitMessagePreparator getPreparator() {
        return new DhKeyExchangeInitMessagePreparator(context.getChooser(), message);
    }

    @Override
    public DhKeyExchangeInitMessageSerializer getSerializer() {
        return new DhKeyExchangeInitMessageSerializer(message);
    }
}
