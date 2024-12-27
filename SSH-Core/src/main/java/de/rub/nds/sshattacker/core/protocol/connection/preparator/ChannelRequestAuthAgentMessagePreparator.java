/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestAuthAgentMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestAuthAgentMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestAuthAgentMessage> {

    public ChannelRequestAuthAgentMessagePreparator() {
        super(ChannelRequestType.AUTH_AGENT_REQ_OPENSSH_COM, true);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents(
            ChannelRequestAuthAgentMessage object, Chooser chooser) {}
}
