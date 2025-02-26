/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelDefaults;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelManager;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessagePreparator
        extends SshMessagePreparator<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    }

    @Override
    public void prepareMessageSpecificContents(
            ChannelOpenConfirmationMessage object, Chooser chooser) {
        ChannelManager channelManager = chooser.getContext().getChannelManager();
        ChannelOpenConfirmationMessage toCopy = channelManager.prepareNextOpenConfirm();

        object.setRecipientChannelId(toCopy.getRecipientChannelId().getValue());
        object.setSenderChannelId(toCopy.getSenderChannelId().getValue());

        Channel channel =
                channelManager.getChannelByLocalId(object.getSenderChannelId().getValue());

        if (channel != null) {
            if (channel.isOpen().getValue()) {
                LOGGER.warn(
                        "Channel with id {} is already open, sending ChannelOpenConfirmationMessage with current channel details again.",
                        channel.getLocalChannelId().getValue());
            }

            object.setWindowSize(channel.getLocalWindowSize().getValue());
            object.setPacketSize(channel.getLocalPacketSize().getValue());
        } else {
            ChannelDefaults channelDefaults = chooser.getConfig().getChannelDefaults();
            object.setWindowSize(channelDefaults.getLocalWindowSize());
            object.setPacketSize(channelDefaults.getLocalPacketSize());
        }
    }
}
