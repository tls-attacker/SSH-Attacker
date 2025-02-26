/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestUnknownMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestUnknownMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestUnknownMessage> {

    public ChannelRequestUnknownMessagePreparator() {
        super("", true);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents(
            ChannelRequestUnknownMessage object, Chooser chooser) {
        object.setTypeSpecificData(new byte[10]);
    }
}
