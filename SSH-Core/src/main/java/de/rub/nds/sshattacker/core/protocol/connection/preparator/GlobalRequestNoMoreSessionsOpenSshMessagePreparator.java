/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestNoMoreSessionsOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestNoMoreSessionsOpenSshMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestNoMoreSessionsOpenSshMessage> {

    public GlobalRequestNoMoreSessionsOpenSshMessagePreparator(
            Chooser chooser, GlobalRequestNoMoreSessionsOpenSshMessage message) {
        super(chooser, message, GlobalRequestType.NO_MORE_SESSIONS_OPENSSH_COM, true);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents() {}
}
