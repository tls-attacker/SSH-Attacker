/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.PongOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.PongOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.PongOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.PongOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PongOpenSshMessageHandler extends SshMessageHandler<PongOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PongOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public PongOpenSshMessageHandler(SshContext context, PongOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        LOGGER.debug(
                "PongMessage received from remote, responded data length: {}",
                message.getDataLength().getValue());
    }

    @Override
    public PongOpenSshMessageParser getParser(byte[] array) {
        return new PongOpenSshMessageParser(array);
    }

    @Override
    public PongOpenSshMessageParser getParser(byte[] array, int startPosition) {
        return new PongOpenSshMessageParser(array, startPosition);
    }

    @Override
    public PongOpenSshMessagePreparator getPreparator() {
        return new PongOpenSshMessagePreparator(context.getChooser(), message);
    }

    @Override
    public PongOpenSshMessageSerializer getSerializer() {
        return new PongOpenSshMessageSerializer(message);
    }
}
