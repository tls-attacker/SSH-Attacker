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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthRequestUnknownMessage
        extends UserAuthRequestMessage<UserAuthRequestUnknownMessage> {
    private ModifiableByteArray methodSpecificFields;

    public UserAuthRequestUnknownMessage() {
        super();
    }

    public UserAuthRequestUnknownMessage(UserAuthRequestUnknownMessage other) {
        super(other);
        methodSpecificFields =
                other.methodSpecificFields != null ? other.methodSpecificFields.createCopy() : null;
    }

    @Override
    public UserAuthRequestUnknownMessage createCopy() {
        return new UserAuthRequestUnknownMessage(this);
    }

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

    public static final UserAuthRequestUnknownMessageHandler HANDLER =
            new UserAuthRequestUnknownMessageHandler();

    @Override
    public UserAuthRequestUnknownMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UserAuthRequestUnknownMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return UserAuthRequestUnknownMessageHandler.SERIALIZER.serialize(this);
    }
}
