/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceRequestMessagePreparator extends Preparator<ServiceRequestMessage> {

    public ServiceRequestMessagePreparator(SshContext context, ServiceRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_SERVICE_REQUEST.id);
        message.setServiceName(context.getChooser().getServiceName());
    }

}
