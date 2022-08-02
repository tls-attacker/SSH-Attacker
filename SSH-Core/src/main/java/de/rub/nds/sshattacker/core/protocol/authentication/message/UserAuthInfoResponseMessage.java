/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationResponse;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthInfoResponseMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.ArrayList;
import java.util.List;

public class UserAuthInfoResponseMessage extends SshMessage<UserAuthInfoResponseMessage> {

    private ModifiableInteger numResponses;
    private List<AuthenticationResponse> responses = new ArrayList<AuthenticationResponse>();

    public UserAuthInfoResponseMessage() {
        super(MessageIdConstant.SSH_MSG_USERAUTH_INFO_RESPONSE);
    }

    public ModifiableInteger getNumResponses() {
        return numResponses;
    }

    public void setNumResponses(ModifiableInteger numResponses) {
        this.numResponses = numResponses;
    }

    public void setNumResponses(int numResponses) {
        this.numResponses =
                ModifiableVariableFactory.safelySetValue(this.numResponses, numResponses);
    }

    public List<AuthenticationResponse> getResponses() {
        return responses;
    }

    public void setResponses(List<AuthenticationResponse> responses) {
        this.responses = responses;
    }

    @Override
    public UserAuthInfoResponseMessageHandler getHandler(SshContext context) {
        return new UserAuthInfoResponseMessageHandler(context, this);
    }
}
