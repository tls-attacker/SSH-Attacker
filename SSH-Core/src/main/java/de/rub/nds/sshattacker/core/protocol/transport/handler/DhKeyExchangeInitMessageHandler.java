/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhKeyExchangeInitMessageHandler extends SshMessageHandler<DhKeyExchangeInitMessage> {

    @Override
    public void adjustContext(SshContext context, DhKeyExchangeInitMessage object) {
        context.getChooser()
                .getDhKeyExchange()
                .setRemotePublicKey(object.getEphemeralPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setDhClientPublicKey(object.getEphemeralPublicKey().getValue());
    }

    @Override
    public DhKeyExchangeInitMessageParser getParser(byte[] array, SshContext context) {
        return new DhKeyExchangeInitMessageParser(array);
    }

    @Override
    public DhKeyExchangeInitMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new DhKeyExchangeInitMessageParser(array, startPosition);
    }

    public static final DhKeyExchangeInitMessagePreparator PREPARATOR =
            new DhKeyExchangeInitMessagePreparator();

    public static final DhKeyExchangeInitMessageSerializer SERIALIZER =
            new DhKeyExchangeInitMessageSerializer();
}
