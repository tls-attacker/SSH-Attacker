/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestNoMoreSessionsMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestNoMoreSessionsMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestNoMoreSessionsMessage> {

    public GlobalRequestNoMoreSessionsMessagePreparator(
            Chooser chooser, GlobalRequestNoMoreSessionsMessage message) {
        super(chooser, message, GlobalRequestType.NO_MORE_SESSIONS_OPENSSH_COM);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents() {}
}
