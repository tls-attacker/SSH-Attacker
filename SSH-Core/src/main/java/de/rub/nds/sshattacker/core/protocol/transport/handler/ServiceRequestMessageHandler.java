/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.ServiceRequestMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.ServiceRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.ServiceRequestMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ServiceRequestMessageHandler extends SshMessageHandler<ServiceRequestMessage> {

    @Override
    public void adjustContext(SshContext context, ServiceRequestMessage object) {
        // TODO: Handle ServiceRequestMessage
    }

    @Override
    public ServiceRequestMessageParser getParser(byte[] array, SshContext context) {
        return new ServiceRequestMessageParser(array);
    }

    @Override
    public ServiceRequestMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ServiceRequestMessageParser(array, startPosition);
    }

    public static final ServiceRequestMessagePreparator PREPARATOR =
            new ServiceRequestMessagePreparator();

    public static final ServiceRequestMessageSerializer SERIALIZER =
            new ServiceRequestMessageSerializer();
}
