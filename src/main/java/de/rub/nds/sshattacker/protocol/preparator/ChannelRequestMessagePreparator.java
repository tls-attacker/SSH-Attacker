/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;

public class ChannelRequestMessagePreparator extends Preparator<ChannelRequestMessage> {

    public ChannelRequestMessagePreparator(SshContext context, ChannelRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_REQUEST.id);
        message.setReplyWanted(context.getChooser().getReplyWanted());
        message.setRequestType(context.getChooser().getChannelRequestType().toString());
        message.setPayload(Converter.stringToLengthPrefixedBinaryString(context.getChooser().getChannelCommand()));
        message.setRecipientChannel(context.getChooser().getRemoteChannel());
    }

}
