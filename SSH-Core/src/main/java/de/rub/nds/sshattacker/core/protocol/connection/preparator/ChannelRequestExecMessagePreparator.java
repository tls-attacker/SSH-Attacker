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
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;

public class ChannelRequestExecMessagePreparator extends Preparator<ChannelRequestExecMessage> {

    public ChannelRequestExecMessagePreparator(
            SshContext context, ChannelRequestExecMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_REQUEST);
        Optional<Integer> remoteChannel = context.getRemoteChannel();
        if (remoteChannel.isPresent()) {
            getObject().setRecipientChannel(remoteChannel.get());
        } else {
            raisePreparationException(
                    "Unable to prepare ChannelRequestExecMessage - No remote channel id set");
            getObject().setRecipientChannel(0);
        }
        getObject().setWantReply(context.getConfig().getReplyWanted());
        getObject().setRequestType(ChannelRequestType.EXEC, true);
        getObject().setCommand(context.getConfig().getChannelCommand(), true);
    }
}
