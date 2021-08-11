/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelExtendedDataMessagePreparator extends Preparator<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessagePreparator(
            SshContext context, ChannelExtendedDataMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_EXTENDED_DATA);

        // TODO dummy values for fuzzing
        message.setRecipientChannel(Integer.MAX_VALUE);
        message.setDataTypeCode(ExtendedChannelDataType.SSH_EXTENDED_DATA_STDERR.getDataTypeCode());
        message.setData(new byte[0], true);
    }
}
