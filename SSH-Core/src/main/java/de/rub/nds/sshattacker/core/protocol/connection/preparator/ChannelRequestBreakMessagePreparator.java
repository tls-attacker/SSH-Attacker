/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestBreakMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestBreakMessagePreparator
        extends SshMessagePreparator<ChannelRequestBreakMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestBreakMessagePreparator(
            Chooser chooser, ChannelRequestBreakMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        Channel channel = null;
        if (getObject().getSenderChannel() != null) {
            channel = chooser.getContext().getChannels().get(getObject().getSenderChannel());
        }

        if (channel == null) {
            channel = chooser.getConfig().getDefaultChannel();
        }
        if (!channel.isOpen().getValue()) {
            LOGGER.info("The required channel is closed, still sending the message!");
        }
        getObject().setRecipientChannel(channel.getRemoteChannel());
        getObject().setWantReply(chooser.getConfig().getReplyWanted());
        getObject().setRequestType(ChannelRequestType.XON_XOFF, true);
        getObject().setBreakLength(chooser.getConfig().getDefaultBreakLength());
    }
}
