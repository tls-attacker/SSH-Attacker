/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.general.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.message.DisconnectMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageHandler extends Ssh1MessageHandler<DisconnectMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageHandler(SshContext sshContext) {
        super(sshContext);
    }

    public void adjustContext(DisconnectMessageSSH1 message) {
        LOGGER.warn(
                "Recieved a Disconnect Message, Reason: {}",
                message.getDisconnectReason().getValue());
        sshContext.setDisconnectMessageReceived(true);
    }
}
