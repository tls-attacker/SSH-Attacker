/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestTcpIpForwardMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestTcpIpForwardMessagePreparator
        extends GlobalRequestMessagePreparator<GlobalRequestTcpIpForwardMessage> {

    public GlobalRequestTcpIpForwardMessagePreparator(
            Chooser chooser, GlobalRequestTcpIpForwardMessage message) {
        super(chooser, message, GlobalRequestType.TCPIP_FORWARD);
    }

    @Override
    protected void prepareGlobalRequestMessageSpecificContents() {
        getObject().setIpAddressToBind("127.0.0.1", true);
        getObject().setPortToBind(22);
    }
}
