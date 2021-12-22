/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.connection.Channel;
import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.workflow.action.MessageAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenMessagePreparator extends SshMessagePreparator<ChannelOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenMessagePreparator(Chooser chooser, ChannelOpenMessage message) {
        super(chooser, message);
    }

    public ChannelOpenMessagePreparator(
            Chooser chooser, ChannelOpenMessage message, Integer senderChannel) {
        super(chooser, message);
        getObject().setSenderChannel(senderChannel);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_OPEN);
        if (getObject().getSenderChannel() == null) {
            throw new PreparationException("Sender channel required to send the message!");
        }
        if (getObject().getWindowSize() == null || getObject().getWindowSize().getValue() == null) {
            getObject().setWindowSize(chooser.getConfig().getDefaultChannel().getlocalWindowSize());
        }
        if (getObject().getPacketSize() == null || getObject().getPacketSize().getValue() == null) {
            getObject().setPacketSize(chooser.getConfig().getDefaultChannel().getlocalPacketSize());
            getObject().setChannelType(ChannelType.SESSION, true);
        }
        if (getObject().getChannelType() == null
                || getObject().getChannelType().getValue() == null) {
            getObject().setChannelType(chooser.getConfig().getDefaultChannel().getChannelType());
        }

        Channel channel =
                MessageAction.getChannels().get(getObject().getSenderChannel().getValue());
        if (channel != null) {
            if (channel.isOpen().getValue()) {
                throw new PreparationException(
                        "Channel of the belonging ChannelOpenMessage is already open!");
            } else {
                channel.setChannelType(
                        ChannelType.getByString(getObject().getChannelType().getValue()));
                channel.setlocalWindowSize(getObject().getWindowSize());
                channel.setRemotePacketSize(getObject().getPacketSize());
                SendAction.getChannels().put(getObject().getSenderChannel().getValue(), channel);
            }
        } else {
            Channel newChannel =
                    new Channel(
                            ChannelType.getByString(getObject().getChannelType().getValue()),
                            getObject().getSenderChannel(),
                            getObject().getWindowSize(),
                            getObject().getPacketSize(),
                            false);
            MessageAction.getChannels().put(getObject().getSenderChannel().getValue(), newChannel);
        }
    }
}
