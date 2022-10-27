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
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationPrompt;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthInfoRequestMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class UserAuthInfoRequestMessage extends SshMessage<UserAuthInfoRequestMessage> {

    private ModifiableInteger userNameLength;
    private ModifiableString userName;
    private ModifiableInteger instructionLength;
    private ModifiableString instruction;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;
    private ModifiableInteger promptEntryCount;
    private AuthenticationPrompt prompt = new AuthenticationPrompt();

    public ModifiableInteger getUserNameLength() {
        return userNameLength;
    }

    public void setUserNameLength(ModifiableInteger userNameLength) {
        this.userNameLength = userNameLength;
    }

    public void setUserNameLength(int userNameLength) {
        this.userNameLength =
                ModifiableVariableFactory.safelySetValue(this.userNameLength, userNameLength);
    }

    public ModifiableString getUserName() {
        return userName;
    }

    public void setUserName(ModifiableString userName) {
        this.userName = userName;
    }

    public void setUserName(String userName) {
        this.userName = ModifiableVariableFactory.safelySetValue(this.userName, userName);
    }

    public void setUserName(ModifiableString userName, boolean adjustLengthField) {
        this.userName = userName;
        if (adjustLengthField) {
            setUserNameLength(this.userName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setUserName(String userName, boolean adjustLengthField) {
        this.userName = ModifiableVariableFactory.safelySetValue(this.userName, userName);
        if (adjustLengthField) {
            setUserNameLength(this.userName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public ModifiableInteger getInstructionLength() {
        return instructionLength;
    }

    public void setInstructionLength(ModifiableInteger instructionLength) {
        this.instructionLength = instructionLength;
    }

    public void setInstructionLength(int instructionLength) {
        this.instructionLength =
                ModifiableVariableFactory.safelySetValue(this.instructionLength, instructionLength);
    }

    public ModifiableString getInstruction() {
        return instruction;
    }

    public void setInstruction(ModifiableString instruction) {
        this.instruction = instruction;
    }

    public void setInstruction(String instruction) {
        this.instruction = ModifiableVariableFactory.safelySetValue(this.instruction, instruction);
    }

    public void setInstruction(ModifiableString instruction, boolean adjustLengthField) {
        this.instruction = instruction;
        if (adjustLengthField) {
            setInstructionLength(
                    this.instruction.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setInstruction(String instruction, boolean adjustLengthField) {
        this.instruction = ModifiableVariableFactory.safelySetValue(this.instruction, instruction);
        if (adjustLengthField) {
            setInstructionLength(
                    this.instruction.getValue().getBytes(StandardCharsets.UTF_8).length);
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

    public ModifiableInteger getPromptEntryCount() {
        return promptEntryCount;
    }

    public void setPromptEntryCount(ModifiableInteger promptEntryCount) {
        this.promptEntryCount = promptEntryCount;
    }

    public void setPromptEntryCount(int promptEntryCount) {
        this.promptEntryCount =
                ModifiableVariableFactory.safelySetValue(this.promptEntryCount, promptEntryCount);
    }

    public AuthenticationPrompt getPrompt() {
        return prompt;
    }

    public void setPrompt(AuthenticationPrompt prompt) {
        this.prompt = prompt;
    }

    @Override
    public UserAuthInfoRequestMessageHandler getHandler(SshContext context) {
        return new UserAuthInfoRequestMessageHandler(context, this);
    }
}
