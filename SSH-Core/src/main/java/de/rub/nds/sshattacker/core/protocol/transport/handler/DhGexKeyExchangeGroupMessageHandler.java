/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeGroupMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeGroupMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeGroupMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeGroupMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeGroupMessage> {

    @Override
    public void adjustContext(SshContext context, DhGexKeyExchangeGroupMessage object) {
        setGroupParametersFromMessage(context, object);
        updateExchangeHashWithGroupParameters(context, object);
    }

    private static void setGroupParametersFromMessage(
            SshContext context, DhGexKeyExchangeGroupMessage msg) {
        DhKeyExchange keyExchange = context.getChooser().getDhGexKeyExchange();
        keyExchange.setModulus(msg.getGroupModulus().getValue());
        keyExchange.setGenerator(msg.getGroupGenerator().getValue());
    }

    private static void updateExchangeHashWithGroupParameters(
            SshContext context, DhGexKeyExchangeGroupMessage msg) {
        ExchangeHashInputHolder inputHolder = context.getExchangeHashInputHolder();
        inputHolder.setDhGexGroupModulus(msg.getGroupModulus().getValue());
        inputHolder.setDhGexGroupGenerator(msg.getGroupGenerator().getValue());
    }

    @Override
    public DhGexKeyExchangeGroupMessageParser getParser(byte[] array, SshContext context) {
        return new DhGexKeyExchangeGroupMessageParser(array);
    }

    @Override
    public DhGexKeyExchangeGroupMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new DhGexKeyExchangeGroupMessageParser(array, startPosition);
    }

    public static final DhGexKeyExchangeGroupMessagePreparator PREPARATOR =
            new DhGexKeyExchangeGroupMessagePreparator();

    public static final DhGexKeyExchangeGroupMessageSerializer SERIALIZER =
            new DhGexKeyExchangeGroupMessageSerializer();
}
