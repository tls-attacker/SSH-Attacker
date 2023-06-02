/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ConnectionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionMessageHandler extends ProtocolMessageHandler<ConnectionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ConnectionMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ConnectionMessage message) {
        sshContext.setLastHandledApplicationMessageData(message.getData().getValue());
        String readableAppData =
                ArrayConverter.bytesToHexString(
                        sshContext.getLastHandledAuthenticationMessageData());
        if (sshContext.getTalkingConnectionEndType()
                == sshContext.getChooser().getMyConnectionPeer()) {
            LOGGER.debug("Received Data:" + readableAppData);
        } else {
            LOGGER.debug("Send Data:" + readableAppData);
        }
    }
}
