/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ChannelCloseConfirmationMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ChannelCloseMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelCloseConfirmationMessageSSHV1Preparator extends SshMessagePreparator<ChannelCloseConfirmationMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelCloseConfirmationMessageSSHV1Preparator(Chooser chooser, ChannelCloseConfirmationMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_MSG_CHANNEL_CLOSE_CONFIRMATION);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        if (getObject().getRemoteChannel() == null) {
            getObject().setRemoteChannel(0);
        }
        LOGGER.debug(getObject().getRemoteChannel().getValue());
    }
}
