/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelTcpIpForwardMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestCancelTcpIpForwardlMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestCancelTcpIpForwardMessage> {

    public GlobalRequestCancelTcpIpForwardlMessagePreparator(
            Chooser chooser, GlobalRequestCancelTcpIpForwardMessage message) {
        super(chooser, message, GlobalRequestType.CANCEL_TCPIP_FORWARD);
    }

    @Override
    public void prepareGlobalRequestMessageSpecificContents() {
        getObject().setIpAddressToBind("127.0.0.1", true);
        getObject().setPortToBind(22);
    }
}
