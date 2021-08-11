/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestExecMessagePreparator extends Preparator<ChannelRequestExecMessage> {

    public ChannelRequestExecMessagePreparator(
            SshContext context, ChannelRequestExecMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_REQUEST);
        message.setRecipientChannel(
                context.getRemoteChannel().orElseThrow(PreparationException::new));
        message.setWantReply(context.getConfig().getReplyWanted());
        message.setRequestType(ChannelRequestType.EXEC, true);
        message.setCommand(context.getConfig().getChannelCommand(), true);
    }
}
