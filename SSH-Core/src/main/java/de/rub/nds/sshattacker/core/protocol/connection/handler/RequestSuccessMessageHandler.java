/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.RequestSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.RequestSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.RequestSuccessMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RequestSuccessMessageHandler extends SshMessageHandler<RequestSuccessMessage> {

    public RequestSuccessMessageHandler(SshContext context) {
        super(context);
    }

    public RequestSuccessMessageHandler(SshContext context, RequestSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle RequestSucessMessage
    }

    @Override
    public SshMessageParser<RequestSuccessMessage> getParser(byte[] array) {
        return new RequestSuccessMessageParser(array);
    }

    @Override
    public SshMessageParser<RequestSuccessMessage> getParser(byte[] array, int startPosition) {
        return new RequestSuccessMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<RequestSuccessMessage> getPreparator() {
        return new RequestSuccessMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<RequestSuccessMessage> getSerializer() {
        return new RequestSuccessMessageSerializer(message);
    }
}
