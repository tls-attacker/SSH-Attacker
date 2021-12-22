/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.handler.RequestSuccessMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RequestSuccessMessage extends ChannelMessage<RequestSuccessMessage> {

    public RequestSuccessMessage() {
        super(MessageIDConstant.SSH_MSG_REQUEST_SUCCESS);
    }

    public RequestSuccessMessage(Integer senderChannel) {
        super(MessageIDConstant.SSH_MSG_REQUEST_SUCCESS, senderChannel);
    }

    @Override
    public RequestSuccessMessageHandler getHandler(SshContext context) {
        return new RequestSuccessMessageHandler(context, this);
    }
}
