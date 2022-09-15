/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthUnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthUnknownMessage extends UserAuthRequestMessage<UserAuthUnknownMessage> {
    private ModifiableByteArray methodSpecificFields;

    public UserAuthUnknownMessage() {
        super();
    }

    public ModifiableByteArray getMethodSpecificFields() {
        return methodSpecificFields;
    }

    public void setPassword(ModifiableByteArray methodSpecificFields) {
        this.methodSpecificFields = methodSpecificFields;
    }

    public void setMethodSpecificFields(byte[] methodSpecificFields) {
        this.methodSpecificFields =
                ModifiableVariableFactory.safelySetValue(
                        this.methodSpecificFields, methodSpecificFields);
    }

    @Override
    public UserAuthUnknownMessageHandler getHandler(SshContext context) {
        return new UserAuthUnknownMessageHandler(context, this);
    }
}
