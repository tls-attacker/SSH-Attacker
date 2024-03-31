/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.DisconnectMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessagePreparator extends Ssh1MessagePreparator<DisconnectMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessagePreparator(Chooser chooser, DisconnectMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_MSG_DISCONNECT);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        if (getObject().getDisconnectReason() == null) {
            getObject().setDisconnectReason("DummyValue");
        }
        LOGGER.debug(getObject().getDisconnectReason().getValue());
    }
}
