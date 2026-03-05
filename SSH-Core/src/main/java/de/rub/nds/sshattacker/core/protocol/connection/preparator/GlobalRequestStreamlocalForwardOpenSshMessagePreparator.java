/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestStreamlocalForwardOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestStreamlocalForwardOpenSshMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestStreamlocalForwardOpenSshMessage> {

    public GlobalRequestStreamlocalForwardOpenSshMessagePreparator() {
        super(GlobalRequestType.STREAMLOCAL_FORWARD_OPENSSH_COM, true);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents(
            GlobalRequestStreamlocalForwardOpenSshMessage object, Chooser chooser) {
        // TODO: Replace dummy values
        object.setSocketPath("/var/run/sshattacker.sock", true);
    }
}
