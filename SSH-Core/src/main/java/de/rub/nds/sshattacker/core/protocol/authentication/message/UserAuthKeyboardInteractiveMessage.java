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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthKeyboardInteractiveMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class UserAuthKeyboardInteractiveMessage
        extends UserAuthRequestMessage<UserAuthKeyboardInteractiveMessage> {

    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;
    private ModifiableInteger subMethodsLength;
    private ModifiableString subMethods;

    public UserAuthKeyboardInteractiveMessage() {
        super();
    }

    public UserAuthKeyboardInteractiveMessage(UserAuthKeyboardInteractiveMessage other) {
        super(other);
        languageTagLength =
                other.languageTagLength != null ? other.languageTagLength.createCopy() : null;
        languageTag = other.languageTag != null ? other.languageTag.createCopy() : null;
        subMethodsLength =
                other.subMethodsLength != null ? other.subMethodsLength.createCopy() : null;
        subMethods = other.subMethods != null ? other.subMethods.createCopy() : null;
    }

    @Override
    public UserAuthKeyboardInteractiveMessage createCopy() {
        return new UserAuthKeyboardInteractiveMessage(this);
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
        this.languageTag = languageTag;
    }

    public void setLanguageTag(String languageTag) {
        this.languageTag = ModifiableVariableFactory.safelySetValue(this.languageTag, languageTag);
    }

    public void setLanguageTag(ModifiableString languageTag, boolean adjustLengthField) {
        this.languageTag = languageTag;
        if (adjustLengthField) {
            setLanguageTagLength(
                    this.languageTag.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setLanguageTag(String languageTag, boolean adjustLengthField) {
        this.languageTag = ModifiableVariableFactory.safelySetValue(this.languageTag, languageTag);
        if (adjustLengthField) {
            setLanguageTagLength(
                    this.languageTag.getValue().getBytes(StandardCharsets.UTF_8).length);
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
                        this.languageTag.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    public ModifiableInteger getSubMethodsLength() {
        return subMethodsLength;
    }

    public void setSubMethodsLength(ModifiableInteger subMethodsLength) {
        this.subMethodsLength = subMethodsLength;
    }

    public void setSubMethodsLength(int subMethodsLength) {
        this.subMethodsLength =
                ModifiableVariableFactory.safelySetValue(this.subMethodsLength, subMethodsLength);
    }

    public ModifiableString getSubMethods() {
        return subMethods;
    }

    public void setSubMethods(ModifiableString subMethods) {
        this.subMethods = subMethods;
    }

    public void setSubMethods(String subMethods) {
        this.subMethods = ModifiableVariableFactory.safelySetValue(this.subMethods, subMethods);
    }

    public void setSubMethods(ModifiableString subMethods, boolean adjustLengthField) {
        this.subMethods = subMethods;
        if (adjustLengthField) {
            setSubMethodsLength(this.subMethods.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSubMethods(String subMethods, boolean adjustLengthField) {
        this.subMethods = ModifiableVariableFactory.safelySetValue(this.subMethods, subMethods);
        if (adjustLengthField) {
            setSubMethodsLength(this.subMethods.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlySubMethods(String subMethods, boolean adjustLengthField, Config config) {
        if (this.subMethods == null || this.subMethods.getOriginalValue() == null) {
            this.subMethods = ModifiableVariableFactory.safelySetValue(this.subMethods, subMethods);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || subMethodsLength == null
                    || subMethodsLength.getOriginalValue() == null) {
                setSubMethodsLength(
                        this.subMethods.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    @Override
    public UserAuthKeyboardInteractiveMessageHandler getHandler(SshContext context) {
        return new UserAuthKeyboardInteractiveMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UserAuthKeyboardInteractiveMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
