/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.SignalType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestExitSignalMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ChannelRequestExitSignalMessage
        extends ChannelRequestMessage<ChannelRequestExitSignalMessage> {

    private ModifiableInteger signalNameLength;
    private ModifiableString signalName;
    private ModifiableBoolean coreDump;
    private ModifiableInteger errorMessageLength;
    private ModifiableString errorMessage;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public ModifiableInteger getSignalNameLength() {
        return signalNameLength;
    }

    public void setSignalNameLength(ModifiableInteger signalNameLength) {
        this.signalNameLength = signalNameLength;
    }

    public void setSignalNameLength(int signalNameLength) {
        this.signalNameLength =
                ModifiableVariableFactory.safelySetValue(this.signalNameLength, signalNameLength);
    }

    public ModifiableString getSignalName() {
        return signalName;
    }

    public void setSignalName(ModifiableString signalName) {
        this.signalName = signalName;
    }

    public void setSignalName(String signalName) {
        this.signalName = ModifiableVariableFactory.safelySetValue(this.signalName, signalName);
    }

    public void setSignalName(SignalType signalName) {
        setSignalName(signalName.toString());
    }

    public void setSignalName(ModifiableString signalName, boolean adjustLengthField) {
        this.signalName = signalName;
        if (adjustLengthField) {
            setSignalNameLength(this.signalName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSignalName(String signalName, boolean adjustLengthField) {
        this.signalName = ModifiableVariableFactory.safelySetValue(this.signalName, signalName);
        if (adjustLengthField) {
            setSignalNameLength(this.signalName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlySignalName(String signalName, boolean adjustLengthField, Config config) {
        if (this.signalName == null || this.signalName.getOriginalValue() == null) {
            this.signalName = ModifiableVariableFactory.safelySetValue(this.signalName, signalName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || signalNameLength == null
                    || signalNameLength.getOriginalValue() == null) {
                setSignalNameLength(
                        this.signalName.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    public void setSignalName(SignalType signalName, boolean adjustLengthField) {
        setSignalName(signalName.toString(), adjustLengthField);
    }

    public ModifiableBoolean getCoreDump() {
        return coreDump;
    }

    public void setCoreDump(boolean coreDump) {
        this.coreDump = ModifiableVariableFactory.safelySetValue(this.coreDump, coreDump);
    }

    public void setSoftlyCoreDump(boolean coreDump) {
        if (this.coreDump == null || this.coreDump.getOriginalValue() == null) {
            this.coreDump = ModifiableVariableFactory.safelySetValue(this.coreDump, coreDump);
        }
    }

    public void setCoreDump(ModifiableBoolean coreDump) {
        this.coreDump = coreDump;
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
        this.languageTag = languageTag;
        if (adjustLengthField) {
            setLanguageTagLength(
                    this.languageTag.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setLanguageTag(String languageTag, boolean adjustLengthField) {
        this.languageTag = ModifiableVariableFactory.safelySetValue(this.languageTag, languageTag);
        if (adjustLengthField) {
            setLanguageTagLength(
                    this.languageTag.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSoftlyLanguageTag(String languageTag, boolean adjustLengthField, Config config) {
        if (this.languageTag == null || this.languageTag.getOriginalValue() == null) {
            this.languageTag =
                    ModifiableVariableFactory.safelySetValue(this.languageTag, languageTag);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || languageTagLength == null
                    || languageTagLength.getOriginalValue() == null) {
                setLanguageTagLength(
                        this.languageTag.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
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
        this.errorMessage = errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage =
                ModifiableVariableFactory.safelySetValue(this.errorMessage, errorMessage);
    }

    public void setErrorMessage(ModifiableString errorMessage, boolean adjustLengthField) {
        this.errorMessage = errorMessage;
        if (adjustLengthField) {
            setErrorMessageLength(
                    this.errorMessage.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setErrorMessage(String errorMessage, boolean adjustLengthField) {
        this.errorMessage =
                ModifiableVariableFactory.safelySetValue(this.errorMessage, errorMessage);
        if (adjustLengthField) {
            setErrorMessageLength(
                    this.errorMessage.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyErrorMessage(
            String errorMessage, boolean adjustLengthField, Config config) {
        if (this.errorMessage == null || this.errorMessage.getOriginalValue() == null) {
            this.errorMessage =
                    ModifiableVariableFactory.safelySetValue(this.errorMessage, errorMessage);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || errorMessageLength == null
                    || errorMessageLength.getOriginalValue() == null) {
                setErrorMessageLength(
                        this.errorMessage.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    @Override
    public ChannelRequestExitSignalMessageHandler getHandler(SshContext context) {
        return new ChannelRequestExitSignalMessageHandler(context, this);
    }
}
