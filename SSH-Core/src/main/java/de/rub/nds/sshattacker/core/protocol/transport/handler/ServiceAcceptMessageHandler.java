/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.ServiceAcceptMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.ServiceAcceptMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.ServiceAcceptMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ServiceAcceptMessageHandler extends SshMessageHandler<ServiceAcceptMessage> {

    @Override
    public void adjustContext(SshContext context, ServiceAcceptMessage object) {
        // TODO: Handle ServiceAcceptMessage
    }

    @Override
    public ServiceAcceptMessageParser getParser(byte[] array, SshContext context) {
        return new ServiceAcceptMessageParser(array);
    }

    @Override
    public ServiceAcceptMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ServiceAcceptMessageParser(array, startPosition);
    }

    public static final ServiceAcceptMessagePreparator PREPARATOR =
            new ServiceAcceptMessagePreparator();

    public static final ServiceAcceptMessageSerializer SERIALIZER =
            new ServiceAcceptMessageSerializer();
}
