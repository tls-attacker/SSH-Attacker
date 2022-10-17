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
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthKeyboardInteractiveMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class UserAuthKeyboardInteractiveMessage
        extends UserAuthRequestMessage<UserAuthKeyboardInteractiveMessage> {

    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;
    private ModifiableInteger subMethodsLength;
    private ModifiableString subMethods;

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
        if (adjustLengthField) {
            setLanguageTagLength(languageTag.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.languageTag = languageTag;
    }

    public void setLanguageTag(String languageTag, boolean adjustLengthField) {
        if (adjustLengthField) {
            setLanguageTagLength(languageTag.getBytes(StandardCharsets.UTF_8).length);
        }
        this.languageTag = ModifiableVariableFactory.safelySetValue(this.languageTag, languageTag);
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
        if (adjustLengthField) {
            setSubMethodsLength(subMethods.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.subMethods = subMethods;
    }

    public void setSubMethods(String subMethods, boolean adjustLengthField) {
        if (adjustLengthField) {
            setSubMethodsLength(subMethods.getBytes(StandardCharsets.UTF_8).length);
        }
        this.subMethods = ModifiableVariableFactory.safelySetValue(this.subMethods, subMethods);
    }

    @Override
    public UserAuthKeyboardInteractiveMessageHandler getHandler(SshContext context) {
        return new UserAuthKeyboardInteractiveMessageHandler(context, this);
    }
}
