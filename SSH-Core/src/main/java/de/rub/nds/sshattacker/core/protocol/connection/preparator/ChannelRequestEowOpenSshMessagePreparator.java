/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEowOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestEowOpenSshMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestEowOpenSshMessage> {

    public ChannelRequestEowOpenSshMessagePreparator(
            Chooser chooser, ChannelRequestEowOpenSshMessage message) {
        super(chooser, message, ChannelRequestType.EOW_OPENSSH_COM, false);
    }

    @Override
    protected void prepareChannelRequestMessageSpecificContents() {}
}
