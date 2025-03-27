/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysProveOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestHostKeysProveOpenSshMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestHostKeysProveOpenSshMessage> {

    public GlobalRequestHostKeysProveOpenSshMessagePreparator(
            Chooser chooser, GlobalRequestHostKeysProveOpenSshMessage message) {
        super(chooser, message, GlobalRequestType.HOSTKEYS_PROVE_00_OPENSSH_COM, false);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents() {
        // TODO: Replace dummy values
        getObject().setHostKeys(chooser.getContext().getHostKey().stream().toList());
    }
}
