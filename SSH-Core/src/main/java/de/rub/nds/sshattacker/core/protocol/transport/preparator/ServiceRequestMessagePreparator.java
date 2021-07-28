/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ServiceRequestMessagePreparator extends Preparator<ServiceRequestMessage> {

    public ServiceRequestMessagePreparator(SshContext context, ServiceRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_SERVICE_REQUEST);
        message.setServiceName(context.getConfig().getServiceName(), true);
    }

}
