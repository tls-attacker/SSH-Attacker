/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ChannelOpenConfirmationMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageSSHV1Handler extends SshMessageHandler<ChannelOpenConfirmationMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessageSSHV1Handler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ChannelOpenConfirmationMessageSSH1 message) {
        LOGGER.warn("Recieved Channel Open Confirmation with remote Channel {} and local Channel", message.getRemoteChannel().getValue());
    }
}
