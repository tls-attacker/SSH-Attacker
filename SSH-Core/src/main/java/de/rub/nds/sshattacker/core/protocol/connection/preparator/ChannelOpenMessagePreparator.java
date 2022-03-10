/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenMessagePreparator extends SshMessagePreparator<ChannelOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenMessagePreparator(Chooser chooser, ChannelOpenMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_OPEN);
        // set transfered value to ChannelType or fallback o config
        if (getObject().getChannelType() == null
                || getObject().getChannelType().getValue() == null) {
            if (getObject().getTransferChannelType() != null) {
                getObject().setChannelType(getObject().getTransferChannelType(), true);
            } else {
                getObject()
                        .setChannelType(
                                chooser.getConfig().getDefaultChannel().getChannelType().toString(),
                                true);
            }
        }
        // set transfered value to ModSenderChannel or fallback to config
        if (getObject().getModSenderChannel() == null
                || getObject().getModSenderChannel().getValue() == null) {
            if (getObject().getSenderChannel() != null) {
                getObject().setModSenderChannel(getObject().getSenderChannel());
            } else {
                throw new PreparationException("Sender channel required to send the message!");
            }
        }
        // set transfered value to WindowSize or fallback to config
        if (getObject().getWindowSize() == null || getObject().getWindowSize().getValue() == null) {
            if (getObject().getTransferWindowSize() != null) {
                getObject().setWindowSize(getObject().getTransferWindowSize());
            } else {
                getObject()
                        .setWindowSize(
                                chooser.getConfig().getDefaultChannel().getlocalWindowSize());
            }
        }
        // set transfered value to PacketSize or fallback to config
        if (getObject().getPacketSize() == null || getObject().getPacketSize().getValue() == null) {
            if (getObject().getTransferPacketSize() != null) {
                getObject().setPacketSize(getObject().getTransferPacketSize());
            } else {
                getObject()
                        .setPacketSize(
                                chooser.getConfig().getDefaultChannel().getlocalPacketSize());
            }
        }

        Channel channel =
                chooser.getContext()
                        .getChannels()
                        .get(getObject().getModSenderChannel().getValue());
        if (channel != null) {
            if (channel.isOpen().getValue()) {
                throw new PreparationException(
                        "Channel of the belonging ChannelOpenMessage is already open!");
            } else {
                channel.setChannelType(
                        ChannelType.getByString(getObject().getChannelType().getValue()));
                channel.setlocalWindowSize(getObject().getWindowSize());
                channel.setRemotePacketSize(getObject().getPacketSize());
                chooser.getContext()
                        .getChannels()
                        .put(getObject().getModSenderChannel().getValue(), channel);
            }
        } else {
            Channel newChannel =
                    new Channel(
                            ChannelType.getByString(getObject().getChannelType().getValue()),
                            getObject().getModSenderChannel(),
                            getObject().getWindowSize(),
                            getObject().getPacketSize(),
                            false);
            chooser.getContext()
                    .getChannels()
                    .put(getObject().getModSenderChannel().getValue(), newChannel);
        }
    }
}
