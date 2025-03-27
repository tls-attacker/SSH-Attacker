/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.PingOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.PingOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.PingOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.PingOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingOpenSshMessageHandler extends SshMessageHandler<PingOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PingOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public PingOpenSshMessageHandler(SshContext context, PingOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        LOGGER.debug(
                "PingMessage received from remote, data to respond length: {}",
                message.getDataLength().getValue());
    }

    @Override
    public PingOpenSshMessageParser getParser(byte[] array) {
        return new PingOpenSshMessageParser(array);
    }

    @Override
    public PingOpenSshMessageParser getParser(byte[] array, int startPosition) {
        return new PingOpenSshMessageParser(array, startPosition);
    }

    @Override
    public PingOpenSshMessagePreparator getPreparator() {
        return new PingOpenSshMessagePreparator(context.getChooser(), message);
    }

    @Override
    public PingOpenSshMessageSerializer getSerializer() {
        return new PingOpenSshMessageSerializer(message);
    }
}
