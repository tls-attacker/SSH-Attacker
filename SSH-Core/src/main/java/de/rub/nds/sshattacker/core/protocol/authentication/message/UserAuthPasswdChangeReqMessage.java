/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthPasswdChangeReqMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class UserAuthPasswdChangeReqMessage extends SshMessage<UserAuthPasswdChangeReqMessage> {

    private ModifiableInteger promptLength;
    private ModifiableString prompt;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public UserAuthPasswdChangeReqMessage() {
        super();
    }

    public UserAuthPasswdChangeReqMessage(UserAuthPasswdChangeReqMessage other) {
        super(other);
        promptLength = other.promptLength != null ? other.promptLength.createCopy() : null;
        prompt = other.prompt != null ? other.prompt.createCopy() : null;
        languageTagLength =
                other.languageTagLength != null ? other.languageTagLength.createCopy() : null;
        languageTag = other.languageTag != null ? other.languageTag.createCopy() : null;
    }

    @Override
    public UserAuthPasswdChangeReqMessage createCopy() {
        return new UserAuthPasswdChangeReqMessage(this);
    }

    public ModifiableInteger getPromptLength() {
        return promptLength;
    }

    public void setPromptLength(ModifiableInteger promptLength) {
        this.promptLength = promptLength;
    }

    public void setPromptLength(int promptLength) {
        this.promptLength =
                ModifiableVariableFactory.safelySetValue(this.promptLength, promptLength);
    }

    public ModifiableString getPrompt() {
        return prompt;
    }

    public void setPrompt(ModifiableString prompt) {
        setPrompt(prompt, false);
    }

    public void setPrompt(String prompt) {
        setPrompt(prompt, false);
    }

    public void setPrompt(ModifiableString prompt, boolean adjustLengthField) {
        this.prompt = prompt;
        if (adjustLengthField) {
            setPromptLength(prompt.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setPrompt(String prompt, boolean adjustLengthField) {
        this.prompt = ModifiableVariableFactory.safelySetValue(this.prompt, prompt);
        if (adjustLengthField) {
            setPromptLength(prompt.getBytes(StandardCharsets.UTF_8).length);
        }
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
            setLanguageTagLength(languageTag.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setLanguageTag(String languageTag, boolean adjustLengthField) {
        this.languageTag = ModifiableVariableFactory.safelySetValue(this.languageTag, languageTag);
        if (adjustLengthField) {
            setLanguageTagLength(languageTag.getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public static final UserAuthPasswdChangeReqMessageHandler HANDLER =
            new UserAuthPasswdChangeReqMessageHandler();

    @Override
    public UserAuthPasswdChangeReqMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UserAuthPasswdChangeReqMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return UserAuthPasswdChangeReqMessageHandler.SERIALIZER.serialize(this);
    }
}
