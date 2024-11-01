/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.SftpStatusCode;
import de.rub.nds.sshattacker.core.data.sftp.handler.response.SftpResponseStatusMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class SftpResponseStatusMessage extends SftpResponseMessage<SftpResponseStatusMessage> {

    private ModifiableInteger statusCode;
    private ModifiableInteger errorMessageLength;
    private ModifiableString errorMessage;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public ModifiableInteger getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(ModifiableInteger statusCode) {
        this.statusCode = statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = ModifiableVariableFactory.safelySetValue(this.statusCode, statusCode);
    }

    public void setStatusCode(SftpStatusCode statusCode) {
        setStatusCode(statusCode.getCode());
    }

    public ModifiableInteger getErrorMessageLength() {
        return errorMessageLength;
    }

    public void setErrorMessageLength(ModifiableInteger errorMessageLength) {
        this.errorMessageLength = errorMessageLength;
    }

    public void setErrorMessageLength(int errorMessageLength) {
        this.errorMessageLength =
                ModifiableVariableFactory.safelySetValue(
                        this.errorMessageLength, errorMessageLength);
    }

    public ModifiableString getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(ModifiableString errorMessage) {
        setErrorMessage(errorMessage, false);
    }

    public void setErrorMessage(String errorMessage) {
        setErrorMessage(errorMessage, false);
    }

    public void setErrorMessage(ModifiableString errorMessage, boolean adjustLengthField) {
        if (adjustLengthField) {
            setErrorMessageLength(errorMessage.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.errorMessage = errorMessage;
    }

    public void setErrorMessage(String errorMessage, boolean adjustLengthField) {
        if (adjustLengthField) {
            setErrorMessageLength(errorMessage.getBytes(StandardCharsets.UTF_8).length);
        }
        this.errorMessage =
                ModifiableVariableFactory.safelySetValue(this.errorMessage, errorMessage);
    }

    public ModifiableInteger getLanguageTagLength() {
        return languageTagLength;
    }

    public void setLanguageTagLength(ModifiableInteger languageTagLength) {
        this.languageTagLength = languageTagLength;
    }

    public void setLanguageTagLength(int languageTagLength) {
        this.languageTagLength =
                ModifiableVariableFactory.safelySetValue(this.languageTagLength, languageTagLength);
    }

    public ModifiableString getLanguageTag() {
        return languageTag;
    }

    public void setLanguageTag(ModifiableString languageTag) {
        setLanguageTag(languageTag, false);
    }

    public void setLanguageTag(String languageTag) {
        setLanguageTag(languageTag, false);
    }

    public void setLanguageTag(ModifiableString languageTag, boolean adjustLengthField) {
        if (adjustLengthField) {
            setLanguageTagLength(languageTag.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.languageTag = languageTag;
    }

    public void setLanguageTag(String languageTag, boolean adjustLengthField) {
        if (adjustLengthField) {
            setLanguageTagLength(languageTag.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.languageTag = ModifiableVariableFactory.safelySetValue(this.languageTag, languageTag);
    }

    @Override
    public SftpResponseStatusMessageHandler getHandler(SshContext context) {
        return new SftpResponseStatusMessageHandler(context, this);
    }
}
