/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.connection.Channel;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.exceptions.MissingChannelException;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestSubsystemMessagePreparator
        extends SshMessagePreparator<ChannelRequestSubsystemMessage> {

    public ChannelRequestSubsystemMessagePreparator(
            Chooser chooser, ChannelRequestSubsystemMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        if (getObject().getSenderChannel() == null) {
            throw new PreparationException("Sender channel required to send the message!");
        }
        Channel channel = chooser.getContext().getChannels().get(getObject().getSenderChannel());
        if (channel == null) {
            throw new MissingChannelException("Can't find the required channel!");
        } else if (channel.isOpen().getValue()) {
            getObject()
                    .setRecipientChannel(
                            Channel.getLocal_remote().get(getObject().getSenderChannel()));
            getObject().setWantReply(chooser.getConfig().getReplyWanted());
            getObject().setRequestType(ChannelRequestType.SUBSYSTEM, true);
            // set transfered value to subsystem name or fallback to config
            if (getObject().getSubsystemName() == null
                    || getObject().getSubsystemName().getValue() == null) {
                if (getObject().getTransferSubsystemName() != null) {
                    getObject().setSubsystemName(getObject().getTransferSubsystemName(), true);
                } else {
                    getObject()
                            .setSubsystemName(chooser.getConfig().getDefaultSubsystemName(), true);
                }
            }
        } else {
            throw new MissingChannelException("Required channel is closed!");
        }
    }
}
