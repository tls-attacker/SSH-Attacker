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
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthRequestUnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestUnknownMessage
        extends UserAuthRequestMessage<UserAuthRequestUnknownMessage> {
    private ModifiableByteArray methodSpecificFields;

    public ModifiableByteArray getMethodSpecificFields() {
        return methodSpecificFields;
    }

    public void setMethodSpecificFields(ModifiableByteArray methodSpecificFields) {
        this.methodSpecificFields = methodSpecificFields;
    }

    public void setMethodSpecificFields(byte[] methodSpecificFields) {
        this.methodSpecificFields =
                ModifiableVariableFactory.safelySetValue(
                        this.methodSpecificFields, methodSpecificFields);
    }

    @Override
    public UserAuthRequestUnknownMessageHandler getHandler(SshContext context) {
        return new UserAuthRequestUnknownMessageHandler(context, this);
    }
}
