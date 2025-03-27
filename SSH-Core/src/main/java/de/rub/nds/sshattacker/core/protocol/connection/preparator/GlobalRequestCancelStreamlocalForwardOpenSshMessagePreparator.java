/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelStreamlocalForwardOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestCancelStreamlocalForwardOpenSshMessagePreparator
        extends GlobalRequestMessagePreparator<
                GlobalRequestCancelStreamlocalForwardOpenSshMessage> {

    public GlobalRequestCancelStreamlocalForwardOpenSshMessagePreparator(
            Chooser chooser, GlobalRequestCancelStreamlocalForwardOpenSshMessage message) {
        super(chooser, message, GlobalRequestType.CANCEL_STREAMLOCAL_FORWARD_OPENSSH_COM, false);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents() {
        // TODO: Replace dummy values
        getObject().setSocketPath("/var/run/sshattacker.sock", true);
    }
}
