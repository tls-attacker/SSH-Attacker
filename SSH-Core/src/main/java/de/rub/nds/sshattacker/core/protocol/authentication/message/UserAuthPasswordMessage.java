/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthPasswordMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthPasswordMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthPasswordMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

import java.nio.charset.StandardCharsets;

public class UserAuthPasswordMessage extends UserAuthRequestMessage<UserAuthPasswordMessage> {

    private ModifiableByte changePassword;
    private ModifiableInteger passwordLength;
    private ModifiableString password;
    private ModifiableInteger newPasswordLength;
    private ModifiableString newPassword;

    public UserAuthPasswordMessage() {
        super(AuthenticationMethod.PASSWORD);
    }

    public ModifiableByte getChangePassword() {
        return changePassword;
    }

    public ModifiableInteger getPasswordLength() {
        return passwordLength;
    }

    public ModifiableString getPassword() {
        return password;
    }

    public ModifiableInteger getNewPasswordLength() {
        return newPasswordLength;
    }

    public ModifiableString getNewPassword() {
        return newPassword;
    }

    public void setChangePassword(ModifiableByte changePassword) {
        this.changePassword = changePassword;
    }

    public void setChangePassword(byte changePassword) {
        this.changePassword = ModifiableVariableFactory.safelySetValue(this.changePassword, changePassword);
    }

    public void setChangePassword(boolean changePassword) {
        setChangePassword(Converter.booleanToByte(changePassword));
    }

    public void setPasswordLength(ModifiableInteger passwordLength) {
        this.passwordLength = passwordLength;
    }

    public void setPasswordLength(int passwordLength) {
        this.passwordLength = ModifiableVariableFactory.safelySetValue(this.passwordLength, passwordLength);
    }

    public void setPassword(ModifiableString password) {
        setPassword(password, true);
    }

    public void setPassword(String password) {
        setPassword(password, true);
    }

    public void setPassword(ModifiableString password, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPasswordLength(password.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.password = password;
    }

    public void setPassword(String password, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPasswordLength(password.getBytes(StandardCharsets.UTF_8).length);
        }
        this.password = ModifiableVariableFactory.safelySetValue(this.password, password);
    }

    public void setNewPasswordLength(ModifiableInteger newPasswordLength) {
        this.newPasswordLength = newPasswordLength;
    }

    public void setNewPasswordLength(int newPasswordLength) {
        this.newPasswordLength = ModifiableVariableFactory.safelySetValue(this.newPasswordLength, newPasswordLength);
    }

    public void setNewPassword(ModifiableString newPassword) {
        setNewPassword(newPassword, true);
    }

    public void setNewPassword(String newPassword) {
        setNewPassword(newPassword, true);
    }

    public void setNewPassword(ModifiableString newPassword, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNewPasswordLength(newPassword.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.newPassword = newPassword;
    }

    public void setNewPassword(String newPassword, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNewPasswordLength(newPassword.getBytes(StandardCharsets.UTF_8).length);
        }
        this.newPassword = ModifiableVariableFactory.safelySetValue(this.newPassword, newPassword);
    }

    @Override
    public UserAuthPasswordMessageHandler getHandler(SshContext context) {
        return new UserAuthPasswordMessageHandler(context);
    }

    @Override
    public UserAuthPasswordMessageSerializer getSerializer() {
        return new UserAuthPasswordMessageSerializer(this);
    }

    @Override
    public UserAuthPasswordMessagePreparator getPreparator(SshContext context) {
        return new UserAuthPasswordMessagePreparator(context, this);
    }

}
