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
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationPrompt;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthInfoRequestMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class UserAuthInfoRequestMessage extends SshMessage<UserAuthInfoRequestMessage> {

    public static final MessageIdConstant ID = MessageIdConstant.SSH_MSG_USERAUTH_INFO_REQUEST;
    private ModifiableInteger userNameLength;
    private ModifiableString userName;
    private ModifiableInteger instructionLength;
    private ModifiableString instruction;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;
    private ModifiableInteger numPrompts;
    private List<AuthenticationPrompt> prompts = new ArrayList<AuthenticationPrompt>();

    public UserAuthInfoRequestMessage() {
        super();
    }

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
        if (adjustLengthField) {
            setUserNameLength(userName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.userName = userName;
    }

    public void setUserName(String userName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setUserNameLength(userName.getBytes(StandardCharsets.UTF_8).length);
        }
        this.userName = ModifiableVariableFactory.safelySetValue(this.userName, userName);
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
        if (adjustLengthField) {
            setInstructionLength(instruction.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.instruction = instruction;
    }

    public void setInstruction(String instruction, boolean adjustLengthField) {
        if (adjustLengthField) {
            setInstructionLength(instruction.getBytes(StandardCharsets.UTF_8).length);
        }
        this.instruction = ModifiableVariableFactory.safelySetValue(this.instruction, instruction);
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

    public ModifiableInteger getNumPrompts() {
        return numPrompts;
    }

    public void setNumPrompts(ModifiableInteger numPrompts) {
        this.numPrompts = numPrompts;
    }

    public void setNumPrompts(int numPrompts) {
        this.numPrompts = ModifiableVariableFactory.safelySetValue(this.numPrompts, numPrompts);
    }

    public List<AuthenticationPrompt> getPrompts() {
        return prompts;
    }

    public void setPrompts(List<AuthenticationPrompt> prompts) {
        this.prompts = prompts;
    }

    @Override
    public UserAuthInfoRequestMessageHandler getHandler(SshContext context) {
        return new UserAuthInfoRequestMessageHandler(context, this);
    }
}
