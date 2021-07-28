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
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ServiceAcceptMessagePreparator extends Preparator<ServiceAcceptMessage> {

    public ServiceAcceptMessagePreparator(SshContext context, ServiceAcceptMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_SERVICE_ACCEPT);
        message.setServiceName("", true);
    }

}
