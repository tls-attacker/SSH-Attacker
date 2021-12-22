/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.connection.Channel;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.exceptions.MissingChannelException;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.workflow.action.MessageAction;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenConfirmationMessagePreparator
        extends SshMessagePreparator<ChannelOpenConfirmationMessage> {

    public ChannelOpenConfirmationMessagePreparator(
            Chooser chooser, ChannelOpenConfirmationMessage message) {
        super(chooser, message);
    }

    public ChannelOpenConfirmationMessagePreparator(
            Chooser chooser, ChannelOpenConfirmationMessage message, Integer senderChannel) {
        super(chooser, message);
        getObject().setSenderChannel(senderChannel);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        // TODO dummy values for fuzzing
        if (getObject().getSenderChannel() == null) {
            throw new PreparationException("Sender channel required to send the message!");
        }
        if (getObject().getWindowSize() == null || getObject().getWindowSize().getValue() == null) {
            getObject().setWindowSize(chooser.getConfig().getDefaultChannel().getlocalWindowSize());
        }
        if (getObject().getPacketSize() == null || getObject().getPacketSize().getValue() == null) {
            getObject().setPacketSize(chooser.getConfig().getDefaultChannel().getlocalPacketSize());
        }
        Channel channel =
                MessageAction.getChannels().get(getObject().getSenderChannel().getValue());
        if (channel == null) {
            throw new MissingChannelException("Can't find the required channel!");
        } else {
            getObject()
                    .setRecipientChannel(
                            Channel.getLocal_remote()
                                    .get(getObject().getSenderChannel().getValue()));
            channel.setRemoteChannel(getObject().getRecipientChannel());
            channel.setOpen(true);
        }
    }
}
