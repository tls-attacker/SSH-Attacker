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
    private final boolean wantReply;

    protected ChannelRequestMessagePreparator(
            Chooser chooser, T message, ChannelRequestType channelRequestType, boolean wantReply) {
        this(chooser, message, channelRequestType.toString(), wantReply);
    }

    protected ChannelRequestMessagePreparator(
            Chooser chooser, T message, String channelRequestType, boolean wantReply) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_REQUEST);
        this.channelRequestType = channelRequestType;
        this.wantReply = wantReply;
    }

    @Override
    protected final void prepareChannelMessageSpecificContents() {
        getObject().setRequestType(channelRequestType, true);
        getObject().setWantReply(wantReply);
        prepareChannelRequestMessageSpecificContents();
    }

    protected abstract void prepareChannelRequestMessageSpecificContents();
}
