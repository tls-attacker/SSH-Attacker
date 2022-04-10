/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.exceptions.MissingChannelException;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenConfirmationMessagePreparator
        extends SshMessagePreparator<ChannelOpenConfirmationMessage> {

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
            } else {
                throw new PreparationException("Sender channel required to send the message!");
            }
        }
        getObject().setPacketSize(chooser.getConfig().getDefaultChannel().getlocalPacketSize());
        getObject().setWindowSize(chooser.getConfig().getDefaultChannel().getlocalWindowSize());
        Channel channel =
                chooser.getContext()
                        .getChannels()
                        .get(getObject().getModSenderChannel().getValue());
        if (channel == null) {
            throw new MissingChannelException("Can't find the required channel!");
        } else {
            getObject()
                    .setRecipientChannel(
                            Channel.getLocal_remote()
                                    .get(getObject().getModSenderChannel().getValue()));
            channel.setRemoteChannel(getObject().getRecipientChannel());
            channel.setOpen(true);
        }
    }
}
