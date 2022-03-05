/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.handler.RequestFailureMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RequestFailureMessage extends ChannelMessage<RequestFailureMessage> {

    public RequestFailureMessage() {
        super(MessageIDConstant.SSH_MSG_REQUEST_FAILURE);
    }

    public RequestFailureMessage(Integer senderChannel) {
        super(MessageIDConstant.SSH_MSG_REQUEST_FAILURE, senderChannel);
    }

    @Override
    public RequestFailureMessageHandler getHandler(SshContext context) {
        return new RequestFailureMessageHandler(context, this);
    }
}
