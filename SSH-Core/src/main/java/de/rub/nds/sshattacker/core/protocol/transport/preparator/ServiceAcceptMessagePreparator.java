/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ServiceAcceptMessagePreparator extends SshMessagePreparator<ServiceAcceptMessage> {

    public ServiceAcceptMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_SERVICE_ACCEPT);
    }

    @Override
    protected void prepareMessageSpecificContents(ServiceAcceptMessage object, Chooser chooser) {
        // TODO: load service name from context
        object.setServiceName(chooser.getConfig().getServiceName(), true);
    }
}
