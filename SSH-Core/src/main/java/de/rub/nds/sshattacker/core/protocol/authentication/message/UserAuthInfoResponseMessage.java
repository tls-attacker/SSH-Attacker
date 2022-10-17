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
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationResponse;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthInfoResponseMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthInfoResponseMessage extends SshMessage<UserAuthInfoResponseMessage> {

    private ModifiableInteger responseEntryCount;
    private AuthenticationResponse response = new AuthenticationResponse();

    public ModifiableInteger getResponseEntryCount() {
        return responseEntryCount;
    }

    public void setResponseEntryCount(ModifiableInteger responseEntryCount) {
        this.responseEntryCount = responseEntryCount;
    }

    public void setResponseEntryCount(int responseEntryCount) {
        this.responseEntryCount =
                ModifiableVariableFactory.safelySetValue(
                        this.responseEntryCount, responseEntryCount);
    }

    public AuthenticationResponse getResponse() {
        return response;
    }

    public void setResponse(AuthenticationResponse response) {
        this.response = response;
    }

    @Override
    public UserAuthInfoResponseMessageHandler getHandler(SshContext context) {
        return new UserAuthInfoResponseMessageHandler(context, this);
    }
}
