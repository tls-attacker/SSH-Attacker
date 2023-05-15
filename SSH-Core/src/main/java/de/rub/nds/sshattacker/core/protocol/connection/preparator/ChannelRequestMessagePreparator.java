/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class ChannelRequestMessagePreparator<T extends ChannelRequestMessage<T>>
        extends ChannelMessagePreparator<T> {

    private final String channelRequestType;

    protected ChannelRequestMessagePreparator(
            Chooser chooser, T message, ChannelRequestType channelRequestType) {
        this(chooser, message, channelRequestType.toString());
    }

    protected ChannelRequestMessagePreparator(
            Chooser chooser, T message, String channelRequestType) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_REQUEST);
        this.channelRequestType = channelRequestType;
    }

    @Override
    protected final void prepareChannelMessageSpecificContents() {
        getObject().setRequestType(channelRequestType, true);
        getObject().setWantReply(false);
        prepareChannelRequestMessageSpecificContents();
    }

    protected abstract void prepareChannelRequestMessageSpecificContents();
}
