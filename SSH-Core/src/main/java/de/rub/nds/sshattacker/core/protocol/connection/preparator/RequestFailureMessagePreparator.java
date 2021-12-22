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
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestFailureMessage;
import de.rub.nds.sshattacker.core.workflow.action.MessageAction;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class RequestFailureMessagePreparator extends SshMessagePreparator<RequestFailureMessage> {

    public RequestFailureMessagePreparator(Chooser chooser, RequestFailureMessage message) {
        super(chooser, message);
    }

    public RequestFailureMessagePreparator(
            Chooser chooser, RequestFailureMessage message, Integer senderChannel) {
        super(chooser, message);
        getObject().setSenderChannel(senderChannel);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_REQUEST_FAILURE);
        if (getObject().getSenderChannel() == null) {
            throw new PreparationException("Sender channel required to send the message!");
        }
        Channel channel =
                MessageAction.getChannels().get(getObject().getSenderChannel().getValue());
        if (channel == null) {
            throw new MissingChannelException("Can't find the required channel!");
        } else if (channel.isOpen().getValue()) {
            getObject()
                    .setRecipientChannel(
                            Channel.getLocal_remote()
                                    .get(getObject().getSenderChannel().getValue()));
        } else {
            throw new MissingChannelException("Required channel is closed!");
        }
    }
}
