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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.core.workflow.action.MessageAction;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenFailureMessagePreparator
        extends SshMessagePreparator<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessagePreparator(Chooser chooser, ChannelOpenFailureMessage message) {
        super(chooser, message);
    }

    public ChannelOpenFailureMessagePreparator(
            Chooser chooser, ChannelOpenFailureMessage message, Integer senderChannel) {
        super(chooser, message);
        getObject().setSenderChannel(senderChannel);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_OPEN_FAILURE);
        // TODO dummy values for fuzzing
        if (getObject().getSenderChannel() == null) {
            throw new PreparationException("Sender channel required to send the message!");
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
            getObject().setReasonCode(Integer.MAX_VALUE);
            getObject().setReason("", true);
            getObject().setLanguageTag("", true);
        }
    }
}
