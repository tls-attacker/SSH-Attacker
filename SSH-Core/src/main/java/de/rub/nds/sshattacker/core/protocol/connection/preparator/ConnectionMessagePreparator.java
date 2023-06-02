/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ConnectionMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionMessagePreparator extends ProtocolMessagePreparator<ConnectionMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConnectionMessage msg;

    public ConnectionMessagePreparator(Chooser chooser, ConnectionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing ApplicationMessage");
        prepareData(msg);
    }

    private void prepareData(ConnectionMessage msg) {
        if (msg.getDataConfig() != null) {
            msg.setData(msg.getDataConfig());
        } else {
            msg.setData(chooser.getLastHandledAuthenticationMessageData());
        }
        LOGGER.debug("Data: {}", msg.getData().getValue());
    }
}
