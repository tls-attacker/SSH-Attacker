/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelDataMessagePreparator extends Preparator<ChannelDataMessage> {

    public ChannelDataMessagePreparator(SshContext context, ChannelDataMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_DATA);

        // TODO dummy values for fuzzing
        getObject().setRecipientChannel(Integer.MAX_VALUE);
        getObject().setData(new byte[0], true);
    }
}
