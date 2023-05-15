/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.ServiceAcceptMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.ServiceAcceptMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.ServiceAcceptMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ServiceAcceptMessageHandler extends SshMessageHandler<ServiceAcceptMessage> {

    public ServiceAcceptMessageHandler(SshContext context) {
        super(context);
    }

    public ServiceAcceptMessageHandler(SshContext context, ServiceAcceptMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ServiceAcceptMessage
    }

    @Override
    public ServiceAcceptMessageParser getParser(byte[] array) {
        return new ServiceAcceptMessageParser(array);
    }

    @Override
    public ServiceAcceptMessageParser getParser(byte[] array, int startPosition) {
        return new ServiceAcceptMessageParser(array, startPosition);
    }

    @Override
    public ServiceAcceptMessagePreparator getPreparator() {
        return new ServiceAcceptMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ServiceAcceptMessageSerializer getSerializer() {
        return new ServiceAcceptMessageSerializer(message);
    }
}
