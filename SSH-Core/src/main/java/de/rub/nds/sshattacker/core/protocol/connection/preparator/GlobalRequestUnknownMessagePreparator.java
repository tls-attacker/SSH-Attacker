/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestUnknownMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestUnknownMessagePreparator
        extends SshMessagePreparator<GlobalRequestUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestUnknownMessagePreparator(
            Chooser chooser, GlobalRequestUnknownMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setWantReply(chooser.getConfig().getReplyWanted());
        getObject().setRequestName("", true);
        getObject().setTypeSpecificData(new byte[0]);
    }
}
