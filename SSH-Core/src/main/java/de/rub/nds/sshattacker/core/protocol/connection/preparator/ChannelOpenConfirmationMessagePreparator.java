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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessagePreparator
        extends SshMessagePreparator<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessagePreparator(
            Chooser chooser, ChannelOpenConfirmationMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    }

    @Override
    public void prepareMessageSpecificContents() {
        ChannelOpenConfirmationMessage toCopy =
                chooser.getContext().getSshContext().getChannelManager().prepareNextOpenConfirm();
        getObject().setRecipientChannelId(toCopy.getRecipientChannelId());
        getObject().setSenderChannelId(toCopy.getSenderChannelId());

        // get the closed Channel
        Channel channel =
                chooser.getContext()
                        .getSshContext()
                        .getChannelManager()
                        .getChannels()
                        .get(toCopy.getRecipientChannelId().getValue());

        if (channel != null) {
            if (channel.isOpen().getValue()) {
                LOGGER.warn(
                        "Channel with id {} is already open, sending ChannelOpenConfirmationMessage with current channel details again.",
                        channel.getLocalChannelId().getValue());
            } else {
                channel.setOpen(true);
            }
        }

        getObject().setWindowSize(chooser.getConfig().getChannelDefaults().getLocalWindowSize());
        getObject().setPacketSize(chooser.getConfig().getChannelDefaults().getLocalPacketSize());
    }
}
