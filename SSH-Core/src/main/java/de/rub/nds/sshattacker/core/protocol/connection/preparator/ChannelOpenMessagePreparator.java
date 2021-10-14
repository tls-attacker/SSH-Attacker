/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenMessagePreparator extends SshMessagePreparator<ChannelOpenMessage> {

    public ChannelOpenMessagePreparator(SshContext context, ChannelOpenMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_OPEN);
        getObject().setSenderChannel(context.getChooser().getLocalChannel());
        getObject().setChannelType(context.getChooser().getChannelType().toString(), true);
        getObject().setWindowSize(context.getChooser().getWindowSize());
        getObject().setPacketSize(context.getChooser().getPacketSize());
    }
}
