/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestOpenSshHostKeysMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestOpenSshHostKeysMessage> {

    public GlobalRequestOpenSshHostKeysMessagePreparator(
            Chooser chooser, GlobalRequestOpenSshHostKeysMessage message) {
        super(chooser, message, GlobalRequestType.HOSTKEYS_00_OPENSSH_COM);
    }

    @Override
    public void prepareGlobalRequestMessageSpecificContents() {
        getObject().setSoftlyHostKeys(chooser.getConfig().getHostKeys());
    }
}
