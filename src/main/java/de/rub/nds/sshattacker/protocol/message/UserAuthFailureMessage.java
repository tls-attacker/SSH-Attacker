package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.UserAuthFailureMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.preparator.UserAuthFailureMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.protocol.serializer.UserAuthFailureMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthFailureMessage extends Message {

    private ModifiableString possibleAuthenticationMethods;
    private ModifiableByte partialSuccess;

    public ModifiableString getPossibleAuthenticationMethods() {
        return possibleAuthenticationMethods;
    }

    public void setPossibleAuthenticationMethods(String possibleAuthenticationMethods) {
        this.possibleAuthenticationMethods = ModifiableVariableFactory.safelySetValue(this.possibleAuthenticationMethods, possibleAuthenticationMethods);
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
    public Handler getHandler(SshContext context) {
        return new UserAuthFailureMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new UserAuthFailureMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new UserAuthFailureMessagePreparator(context, this);
    }

}
