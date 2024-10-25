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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthUnknownMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.io.InputStream;

public class UserAuthUnknownMessage extends UserAuthRequestMessage<UserAuthUnknownMessage> {
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
    public UserAuthUnknownMessageHandler getHandler(SshContext context) {
        return new UserAuthUnknownMessageHandler(context);
    }

    @Override
    public SshMessageParser<UserAuthUnknownMessage> getParser(
            SshContext context, InputStream stream) {
        return new UserAuthUnknownMessageParser(stream);
    }

    @Override
    public UserAuthUnknownMessagePreparator getPreparator(SshContext context) {
        return new UserAuthUnknownMessagePreparator(context.getChooser(), this);
    }

    @Override
    public UserAuthUnknownMessageSerializer getSerializer(SshContext context) {
        return new UserAuthUnknownMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "USERAUTH_Unnkown";
    }
}
