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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthFailureMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

public class UserAuthFailureMessage extends SshMessage<UserAuthFailureMessage> {

    private ModifiableInteger possibleAuthenticationMethodsLength;
    private ModifiableString possibleAuthenticationMethods;
    private ModifiableByte partialSuccess;

    public UserAuthFailureMessage() {
        super(MessageIdConstant.SSH_MSG_USERAUTH_FAILURE);
    }

    public ModifiableInteger getPossibleAuthenticationMethodsLength() {
        return possibleAuthenticationMethodsLength;
    }

    public void setPossibleAuthenticationMethodsLength(
            ModifiableInteger possibleAuthenticationMethodsLength) {
        this.possibleAuthenticationMethodsLength = possibleAuthenticationMethodsLength;
    }

    public void setPossibleAuthenticationMethodsLength(int possibleAuthenticationMethodsLength) {
        this.possibleAuthenticationMethodsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.possibleAuthenticationMethodsLength,
                        possibleAuthenticationMethodsLength);
    }

    public ModifiableString getPossibleAuthenticationMethods() {
        return possibleAuthenticationMethods;
    }

    public void setPossibleAuthenticationMethods(ModifiableString possibleAuthenticationMethods) {
        setPossibleAuthenticationMethods(possibleAuthenticationMethods, false);
    }

    public void setPossibleAuthenticationMethods(String possibleAuthenticationMethods) {
        setPossibleAuthenticationMethods(possibleAuthenticationMethods, false);
    }

    public void setPossibleAuthenticationMethods(String[] possibleAuthenticationMethods) {
        setPossibleAuthenticationMethods(possibleAuthenticationMethods, false);
    }

    public void setPossibleAuthenticationMethods(
            List<AuthenticationMethod> possibleAuthenticationMethods) {
        setPossibleAuthenticationMethods(possibleAuthenticationMethods, false);
    }

    public void setPossibleAuthenticationMethods(
            ModifiableString possibleAuthenticationMethods, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPossibleAuthenticationMethodsLength(
                    possibleAuthenticationMethods
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
        this.possibleAuthenticationMethods = possibleAuthenticationMethods;
    }

    public void setPossibleAuthenticationMethods(
            String possibleAuthenticationMethods, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPossibleAuthenticationMethodsLength(
                    possibleAuthenticationMethods.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.possibleAuthenticationMethods =
                ModifiableVariableFactory.safelySetValue(
                        this.possibleAuthenticationMethods, possibleAuthenticationMethods);
    }

    public void setPossibleAuthenticationMethods(
            String[] possibleAuthenticationMethods, boolean adjustLengthField) {
        String nameList =
                String.join("" + CharConstants.ALGORITHM_SEPARATOR, possibleAuthenticationMethods);
        setPossibleAuthenticationMethods(nameList, adjustLengthField);
    }

    public void setPossibleAuthenticationMethods(
            List<AuthenticationMethod> possibleAuthenticationMethods, boolean adjustLengthField) {
        String nameList =
                possibleAuthenticationMethods.stream()
                        .map(AuthenticationMethod::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setPossibleAuthenticationMethods(nameList, adjustLengthField);
    }

    public ModifiableByte getPartialSuccess() {
        return partialSuccess;
    }

    public void setPartialSuccess(ModifiableByte partialSuccess) {
        this.partialSuccess = partialSuccess;
    }

    public void setPartialSuccess(byte partialSuccess) {
        this.partialSuccess =
                ModifiableVariableFactory.safelySetValue(this.partialSuccess, partialSuccess);
    }

    public void setPartialSuccess(boolean partialSuccess) {
        setPartialSuccess(Converter.booleanToByte(partialSuccess));
    }

    @Override
    public UserAuthFailureMessageHandler getHandler(SshContext context) {
        return new UserAuthFailureMessageHandler(context, this);
    }
}
