/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelExtendedDataMessagePreparator
        extends ChannelMessagePreparator<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_CHANNEL_EXTENDED_DATA);
    }

    @Override
    protected void prepareChannelMessageSpecificContents(
            ChannelExtendedDataMessage object, Chooser chooser) {
        // TODO dummy values for fuzzing
        object.setDataTypeCode(ExtendedChannelDataType.SSH_EXTENDED_DATA_STDERR.getDataTypeCode());
        object.setData(new byte[100], true);
    }
}
