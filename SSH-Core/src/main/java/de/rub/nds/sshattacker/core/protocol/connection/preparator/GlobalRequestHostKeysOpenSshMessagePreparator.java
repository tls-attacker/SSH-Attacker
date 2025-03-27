/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestHostKeysOpenSshMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestHostKeysOpenSshMessage> {

    public GlobalRequestHostKeysOpenSshMessagePreparator(
            Chooser chooser, GlobalRequestHostKeysOpenSshMessage message) {
        super(chooser, message, GlobalRequestType.HOSTKEYS_00_OPENSSH_COM, false);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents() {
        getObject().setHostKeys(chooser.getConfig().getHostKeys());
    }
}
