/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.TcpIpForwardCancelMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class TcpIpForwardCancelMessagePreparator extends SshMessagePreparator<TcpIpForwardCancelMessage> {
    
    public TcpIpForwardCancelMessagePreparator(SshContext context, TcpIpForwardCancelMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_GLOBAL_REQUEST);
        getObject().setRequestName(GlobalRequestType.CANCEL_TCPIP_FORWARD, true);
        getObject().setWantReply((byte) 1);
        getObject().setIPAddressToBind("127.0.0.1", true);
        getObject().setPortToBind(22);
    }
}
