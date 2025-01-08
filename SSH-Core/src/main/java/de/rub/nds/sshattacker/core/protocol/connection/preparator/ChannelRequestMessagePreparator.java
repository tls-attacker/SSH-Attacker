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
            ChannelRequestType channelRequestType, boolean wantReply) {
        this(channelRequestType.toString(), wantReply);
    }

    protected ChannelRequestMessagePreparator(String channelRequestType, boolean wantReply) {
        super(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST);
        this.channelRequestType = channelRequestType;
        this.wantReply = wantReply;
    }

    @Override
    protected final void prepareChannelMessageSpecificContents(T object, Chooser chooser) {
        // Always set correct channel request type -> Don't use soft set
        object.setRequestType(channelRequestType, true);
        object.setSoftlyWantReply(wantReply);
        prepareChannelRequestMessageSpecificContents(object, chooser);
    }

    protected abstract void prepareChannelRequestMessageSpecificContents(T object, Chooser chooser);
}
