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

    @Override
    public void adjustContext(SshContext context, PongOpenSshMessage object) {
        LOGGER.debug(
                "PongOpenSshMessage received from remote, responded data length: {}",
                () -> object.getDataLength().getValue());
    }

    @Override
    public PongOpenSshMessageParser getParser(byte[] array, SshContext context) {
        return new PongOpenSshMessageParser(array);
    }

    @Override
    public PongOpenSshMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new PongOpenSshMessageParser(array, startPosition);
    }

    public static final PongOpenSshMessagePreparator PREPARATOR =
            new PongOpenSshMessagePreparator();

    public static final PongOpenSshMessageSerializer SERIALIZER =
            new PongOpenSshMessageSerializer();
}
