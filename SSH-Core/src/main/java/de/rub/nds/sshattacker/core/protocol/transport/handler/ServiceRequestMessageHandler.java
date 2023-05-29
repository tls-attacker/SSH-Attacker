/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;

public class ServiceRequestMessageHandler extends SshMessageHandler<ServiceRequestMessage> {

    public ServiceRequestMessageHandler(SshContext context) {
        super(context);
    }

    /*public ServiceRequestMessageHandler(SshContext context, ServiceRequestMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(ServiceRequestMessage message) {
        // TODO: Handle ServiceRequestMessage
    }

    /*@Override
    public ServiceRequestMessageParser getParser(byte[] array) {
        return new ServiceRequestMessageParser(array);
    }

    @Override
    public ServiceRequestMessageParser getParser(byte[] array, int startPosition) {
        return new ServiceRequestMessageParser(array, startPosition);
    }

    @Override
    public ServiceRequestMessagePreparator getPreparator() {
        return new ServiceRequestMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ServiceRequestMessageSerializer getSerializer() {
        return new ServiceRequestMessageSerializer(message);
    }*/
}
