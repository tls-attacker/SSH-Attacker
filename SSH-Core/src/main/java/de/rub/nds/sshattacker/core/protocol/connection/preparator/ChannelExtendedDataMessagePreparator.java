/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelExtendedDataMessagePreparator
        extends SshMessagePreparator<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessagePreparator(
            Chooser chooser, ChannelExtendedDataMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_EXTENDED_DATA);
        // TODO dummy values for fuzzing
        getObject().setRecipientChannel(chooser.getRemoteChannel());
        getObject()
                .setDataTypeCode(
                        ExtendedChannelDataType.SSH_EXTENDED_DATA_STDERR.getDataTypeCode());
        getObject().setData(new byte[0], true);
    }
}
