/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

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
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        // TODO dummy values for fuzzing
        // set transfered value to ModSenderChannel or fallback to config
        if (getObject().getModSenderChannel() == null
                || getObject().getModSenderChannel().getValue() == null) {
            if (getObject().getSenderChannel() != null) {
                getObject().setModSenderChannel(getObject().getSenderChannel());
            }
        }
        Channel channel =
                chooser.getContext()
                        .getChannels()
                        .get(getObject().getModSenderChannel().getValue());
        if (channel == null) {
            channel = chooser.getConfig().getDefaultChannel();
        }
        getObject().setPacketSize(chooser.getConfig().getDefaultChannel().getlocalPacketSize());
        getObject().setWindowSize(chooser.getConfig().getDefaultChannel().getlocalWindowSize());

        getObject().setRecipientChannel(channel.getRemoteChannel());
        channel.setRemoteChannel(getObject().getRecipientChannel());
        channel.setOpen(true);
    }
}
