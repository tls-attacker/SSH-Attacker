/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEnvMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestEnvMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestEnvMessage> {

    public ChannelRequestEnvMessagePreparator() {
        super(ChannelRequestType.ENV, true);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents(
            ChannelRequestEnvMessage object, Chooser chooser) {
        object.setSoftlyVariableName(
                chooser.getConfig().getDefaultVariableName(), true, chooser.getConfig());
        object.setSoftlyVariableValue(
                chooser.getConfig().getDefaultVariableValue(), true, chooser.getConfig());
    }
}
