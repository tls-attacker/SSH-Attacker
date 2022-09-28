/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
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
        // set transfered value to ModSenderChannel or fallback to config
        if (getObject().getModSenderChannel() == null
                || getObject().getModSenderChannel().getValue() == null) {
            if (getObject().getSenderChannel() != null) {
                getObject().setModSenderChannel(getObject().getSenderChannel());

            } else {
                getObject()
                        .setModSenderChannel(
                                chooser.getConfig().getDefaultChannel().getLocalChannel());
                chooser.getContext()
                        .getChannels()
                        .put(
                                getObject().getModSenderChannel().getValue(),
                                chooser.getConfig().getDefaultChannel());
            }
        }
        Channel channel =
                chooser.getContext()
                        .getChannels()
                        .get(getObject().getModSenderChannel().getValue());

        getObject().setChannelType(chooser.getConfig().getDefaultChannel().getChannelType(), true);
        getObject().setWindowSize(chooser.getConfig().getDefaultChannel().getLocalWindowSize());
        getObject().setPacketSize(chooser.getConfig().getDefaultChannel().getlocalPacketSize());

        if (channel != null) {
            if (channel.isOpen().getValue()) {
                LOGGER.info(
                        "Channel of the belonging ChannelOpenMessage is already open, changing channel "
                                + "details and sending ChannelOpenMessage again!");
            }
            channel.setChannelType(
                    ChannelType.getByString(getObject().getChannelType().getValue()));
            channel.setLocalWindowSize(getObject().getWindowSize());
            channel.setRemotePacketSize(getObject().getPacketSize());
            chooser.getContext()
                    .getChannels()
                    .put(getObject().getModSenderChannel().getValue(), channel);

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
