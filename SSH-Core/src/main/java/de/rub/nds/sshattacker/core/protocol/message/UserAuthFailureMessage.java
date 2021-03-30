/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.preparator.UserAuthFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.serializer.UserAuthFailureMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.handler.UserAuthFailureMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthFailureMessage extends Message<UserAuthFailureMessage> {

    private ModifiableString possibleAuthenticationMethods;
    private ModifiableByte partialSuccess;

    public ModifiableString getPossibleAuthenticationMethods() {
        return possibleAuthenticationMethods;
    }

    public void setPossibleAuthenticationMethods(String possibleAuthenticationMethods) {
        this.possibleAuthenticationMethods = ModifiableVariableFactory.safelySetValue(
                this.possibleAuthenticationMethods, possibleAuthenticationMethods);
    }

    public ModifiableByte getPartialSuccess() {
        return partialSuccess;
    }

    public void setPartialSuccess(ModifiableByte partialSuccess) {
        this.partialSuccess = partialSuccess;
    }

    public void setPartialSuccess(byte partialSuccess) {
        this.partialSuccess = ModifiableVariableFactory.safelySetValue(this.partialSuccess, partialSuccess);
    }

    @Override
    public UserAuthFailureMessageHandler getHandler(SshContext context) {
        return new UserAuthFailureMessageHandler(context);
    }

    @Override
    public UserAuthFailureMessageSerializer getSerializer() {
        return new UserAuthFailureMessageSerializer(this);
    }

    @Override
    public UserAuthFailureMessagePreparator getPreparator(SshContext context) {
        return new UserAuthFailureMessagePreparator(context, this);
    }

}
