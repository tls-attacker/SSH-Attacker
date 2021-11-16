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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeInitMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public DhGexKeyExchangeInitMessageHandler(
            SshContext context, DhGexKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle DhGexKeyExchangeInitMessage
    }

    @Override
    public SshMessageParser<DhGexKeyExchangeInitMessage> getParser(
            byte[] array, int startPosition) {
        return new DhGexKeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeInitMessagePreparator getPreparator() {
        return new DhGexKeyExchangeInitMessagePreparator(context.getChooser(), message);
    }

    @Override
    public DhGexKeyExchangeInitMessageSerializer getSerializer() {
        return new DhGexKeyExchangeInitMessageSerializer(message);
    }
}
