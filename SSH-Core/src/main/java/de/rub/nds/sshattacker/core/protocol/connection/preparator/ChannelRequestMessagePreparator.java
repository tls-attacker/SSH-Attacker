/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestMessagePreparator extends Preparator<ChannelRequestMessage> {

    public ChannelRequestMessagePreparator(SshContext context, ChannelRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_REQUEST.id);
        message.setReplyWanted(context.getConfig().getReplyWanted());
        message.setRequestType(context.getConfig().getChannelRequestType().toString());
        message.setPayload(Converter.stringToLengthPrefixedBinaryString(context.getConfig().getChannelCommand()));
        message.setRecipientChannel(context.getRemoteChannel().orElseThrow(PreparationException::new));
    }
}
