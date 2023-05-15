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
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthPasswordMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

import java.nio.charset.StandardCharsets;

public class UserAuthPasswordMessage extends UserAuthRequestMessage<UserAuthPasswordMessage> {

    private ModifiableByte changePassword;
    private ModifiableInteger passwordLength;
    private ModifiableString password;
    private ModifiableInteger newPasswordLength;
    private ModifiableString newPassword;

    public ModifiableByte getChangePassword() {
        return changePassword;
    }

    public void setChangePassword(ModifiableByte changePassword) {
        this.changePassword = changePassword;
    }

    public void setChangePassword(byte changePassword) {
        this.changePassword =
                ModifiableVariableFactory.safelySetValue(this.changePassword, changePassword);
    }

    public void setChangePassword(boolean changePassword) {
        setChangePassword(Converter.booleanToByte(changePassword));
    }

    public ModifiableInteger getPasswordLength() {
        return passwordLength;
    }

    public void setPasswordLength(ModifiableInteger passwordLength) {
        this.passwordLength = passwordLength;
    }

    public void setPasswordLength(int passwordLength) {
        this.passwordLength =
                ModifiableVariableFactory.safelySetValue(this.passwordLength, passwordLength);
    }

    public ModifiableString getPassword() {
        return password;
    }

    public void setPassword(ModifiableString password) {
        setPassword(password, false);
    }

    public void setPassword(String password) {
        setPassword(password, false);
    }

    public void setPassword(ModifiableString password, boolean adjustLengthField) {
        this.password = password;
        if (adjustLengthField) {
            setPasswordLength(this.password.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setPassword(String password, boolean adjustLengthField) {
        this.password = ModifiableVariableFactory.safelySetValue(this.password, password);
        if (adjustLengthField) {
            setPasswordLength(this.password.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public ModifiableInteger getNewPasswordLength() {
        return newPasswordLength;
    }

    public void setNewPasswordLength(ModifiableInteger newPasswordLength) {
        this.newPasswordLength = newPasswordLength;
    }

    public void setNewPasswordLength(int newPasswordLength) {
        this.newPasswordLength =
                ModifiableVariableFactory.safelySetValue(this.newPasswordLength, newPasswordLength);
    }

    public ModifiableString getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(ModifiableString newPassword) {
        setNewPassword(newPassword, false);
    }

    public void setNewPassword(String newPassword) {
        setNewPassword(newPassword, false);
    }

    public void setNewPassword(ModifiableString newPassword, boolean adjustLengthField) {
        this.newPassword = newPassword;
        if (adjustLengthField) {
            setNewPasswordLength(
                    this.newPassword.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setNewPassword(String newPassword, boolean adjustLengthField) {
        this.newPassword = ModifiableVariableFactory.safelySetValue(this.newPassword, newPassword);
        if (adjustLengthField) {
            setNewPasswordLength(
                    this.newPassword.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    @Override
    public UserAuthPasswordMessageHandler getHandler(SshContext context) {
        return new UserAuthPasswordMessageHandler(context, this);
    }
}
