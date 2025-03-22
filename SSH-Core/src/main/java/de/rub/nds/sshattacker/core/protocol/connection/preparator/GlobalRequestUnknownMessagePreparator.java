/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestUnknownMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestUnknownMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestUnknownMessage> {

    public GlobalRequestUnknownMessagePreparator() {
        super("hello-from@ssh-attacker.de", true);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents(
            GlobalRequestUnknownMessage object, Chooser chooser) {
        object.setTypeSpecificData(new byte[10]);
    }
}
