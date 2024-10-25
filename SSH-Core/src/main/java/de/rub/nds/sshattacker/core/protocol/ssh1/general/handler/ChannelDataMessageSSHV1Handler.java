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
import de.rub.nds.sshattacker.core.protocol.ssh1.general.message.ChannelDataMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelDataMessageSSHV1Handler extends Ssh1MessageHandler<ChannelDataMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessageSSHV1Handler(SshContext sshContext) {
        super(sshContext);
    }

    @Override
    public void adjustContext(ChannelDataMessageSSH1 message) {
        LOGGER.warn(
                "Recieved channel Data in channel {} with data {}",
                message.getRemoteChannel().getValue(),
                message.getData().getValue());
    }
}
