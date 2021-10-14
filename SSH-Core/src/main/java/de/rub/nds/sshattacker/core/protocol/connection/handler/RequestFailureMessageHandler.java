/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.RequestFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.RequestFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.RequestFailureMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RequestFailureMessageHandler extends SshMessageHandler<RequestFailureMessage> {

    public RequestFailureMessageHandler(SshContext context) {
        super(context);
    }

    public RequestFailureMessageHandler(SshContext context, RequestFailureMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle RequestFailureMessage
    }

    @Override
    public RequestFailureMessageParser getParser(byte[] array, int startPosition) {
        return new RequestFailureMessageParser(array, startPosition);
    }

    @Override
    public RequestFailureMessagePreparator getPreparator() {
        return new RequestFailureMessagePreparator(context, message);
    }

    @Override
    public RequestFailureMessageSerializer getSerializer() {
        return new RequestFailureMessageSerializer(message);
    }
}
