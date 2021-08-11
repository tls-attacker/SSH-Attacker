/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.connection.handler.RequestSuccessMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.RequestSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.RequestSuccessMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RequestSuccessMessage extends Message<RequestSuccessMessage> {

    public RequestSuccessMessage() {
        super(MessageIDConstant.SSH_MSG_REQUEST_SUCCESS);
    }

    @Override
    public RequestSuccessMessageHandler getHandler(SshContext context) {
        return new RequestSuccessMessageHandler(context);
    }

    @Override
    public RequestSuccessMessageSerializer getSerializer() {
        return new RequestSuccessMessageSerializer(this);
    }

    @Override
    public RequestSuccessMessagePreparator getPreparator(SshContext context) {
        return new RequestSuccessMessagePreparator(context, this);
    }
}
