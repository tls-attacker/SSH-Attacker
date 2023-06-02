/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageHandler extends SshMessageHandler<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageHandler(SshContext context) {
        super(context);
    }

    /*public DisconnectMessageHandler(SshContext context, DisconnectMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(DisconnectMessage message) {
        LOGGER.info("Received DisconnectMessage");
        sshContext.setDisconnectMessageReceived(true);
    }

    /*@Override
    public DisconnectMessageParser getParser(byte[] array) {
        return new DisconnectMessageParser(array);
    }

    @Override
    public DisconnectMessageParser getParser(byte[] array, int startPosition) {
        return new DisconnectMessageParser(array, startPosition);
    }

    @Override
    public DisconnectMessagePreparator getPreparator() {
        return new DisconnectMessagePreparator(context.getChooser(), message);
    }

    @Override
    public DisconnectMessageSerializer getSerializer() {
        return new DisconnectMessageSerializer(message);
    }*/
}
