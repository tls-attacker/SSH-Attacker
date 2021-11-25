/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeRequestMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeRequestMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeRequestMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeRequestMessageHandler(SshContext context) {
        super(context);
    }

    public DhGexKeyExchangeRequestMessageHandler(
            SshContext context, DhGexKeyExchangeRequestMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle DhGexKeyExchangeRequestMessage
    }

    @Override
    public SshMessageParser<DhGexKeyExchangeRequestMessage> getParser(
            byte[] array, int startPosition) {
        return new DhGexKeyExchangeRequestMessageParser(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeRequestMessagePreparator getPreparator() {
        return new DhGexKeyExchangeRequestMessagePreparator(context.getChooser(), message);
    }

    @Override
    public DhGexKeyExchangeRequestMessageSerializer getSerializer() {
        return new DhGexKeyExchangeRequestMessageSerializer(message);
    }
}
