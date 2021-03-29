/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.sshattacker.protocol.handler.RequestFailureMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.RequestFailureMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.RequestFailureMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class RequestFailureMessage extends Message<RequestFailureMessage> {

    @Override
    public RequestFailureMessageHandler getHandler(SshContext context) {
        return new RequestFailureMessageHandler(context);
    }

    @Override
    public RequestFailureMessageSerializer getSerializer() {
        return new RequestFailureMessageSerializer(this);
    }

    @Override
    public RequestFailureMessagePreparator getPreparator(SshContext context) {
        return new RequestFailureMessagePreparator(context, this);
    }

}
