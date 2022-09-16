/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationResponse;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoResponseMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthInfoResponseMessagePreparator
        extends SshMessagePreparator<UserAuthInfoResponseMessage> {

    public UserAuthInfoResponseMessagePreparator(
            Chooser chooser, UserAuthInfoResponseMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setResponseEntryCount(0);
        for (int i = 0; i < chooser.getConfig().getPreConfiguredAuthResponses().size(); i++) {
            AuthenticationResponse authenticationResponse =
                    chooser.getConfig().getPreConfiguredAuthResponses().get(i);
            if (authenticationResponse.get(0).isExecuted()) {
                i++;
            } else {
                getObject().setResponse(authenticationResponse);
                getObject().setResponseEntryCount(authenticationResponse.size());
                authenticationResponse.get(0).setExecuted(true);
                break;
            }
        }
    }
}
