/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthInfoRequestMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class UserAuthInfoRequestMessage extends SshMessage<UserAuthInfoRequestMessage> {

    private ModifiableInteger userNameLength;
    private ModifiableString userName;
    private ModifiableInteger instructionLength;
    private ModifiableString instruction;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;
    private ModifiableInteger promptEntriesCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            @XmlElement(type = AuthenticationPromptEntry.class, name = "AuthenticationPromptEntry"))
    private ArrayList<AuthenticationPromptEntry> promptEntries = new ArrayList<>();

    public UserAuthInfoRequestMessage() {
        super();
    }

    public UserAuthInfoRequestMessage(UserAuthInfoRequestMessage other) {
        super(other);
        userNameLength = other.userNameLength != null ? other.userNameLength.createCopy() : null;
        userName = other.userName != null ? other.userName.createCopy() : null;
        instructionLength =
                other.instructionLength != null ? other.instructionLength.createCopy() : null;
        instruction = other.instruction != null ? other.instruction.createCopy() : null;
        languageTagLength =
                other.languageTagLength != null ? other.languageTagLength.createCopy() : null;
        languageTag = other.languageTag != null ? other.languageTag.createCopy() : null;
        promptEntriesCount =
                other.promptEntriesCount != null ? other.promptEntriesCount.createCopy() : null;
        if (other.promptEntries != null) {
            promptEntries = new ArrayList<>(other.promptEntries.size());
            for (AuthenticationPromptEntry item : other.promptEntries) {
                promptEntries.add(item != null ? item.createCopy() : null);
            }
        }
    }

    @Override
    public UserAuthInfoRequestMessage createCopy() {
        return new UserAuthInfoRequestMessage(this);
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

    public void setSoftlyUserName(String userName, boolean adjustLengthField, Config config) {
        if (this.userName == null || this.userName.getOriginalValue() == null) {
            this.userName = ModifiableVariableFactory.safelySetValue(this.userName, userName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || userNameLength == null
                    || userNameLength.getOriginalValue() == null) {
                setUserNameLength(this.userName.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
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

    public void setSoftlyInstruction(String instruction, boolean adjustLengthField, Config config) {
        if (this.instruction == null || this.instruction.getOriginalValue() == null) {
            this.instruction =
                    ModifiableVariableFactory.safelySetValue(this.instruction, instruction);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || instructionLength == null
                    || instructionLength.getOriginalValue() == null) {
                setInstructionLength(
                        this.instruction.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
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

    public ModifiableInteger getPromptEntriesCount() {
        return promptEntriesCount;
    }

    public void setPromptEntriesCount(ModifiableInteger promptEntriesCount) {
        this.promptEntriesCount = promptEntriesCount;
    }

    public void setPromptEntriesCount(int promptEntriesCount) {
        this.promptEntriesCount =
                ModifiableVariableFactory.safelySetValue(
                        this.promptEntriesCount, promptEntriesCount);
    }

    public void setSoftlyPromptEntriesCount(int promptEntriesCount, Config config) {
        if (config.getAlwaysPrepareLengthFields()
                || this.promptEntriesCount == null
                || this.promptEntriesCount.getOriginalValue() == null) {
            this.promptEntriesCount =
                    ModifiableVariableFactory.safelySetValue(
                            this.promptEntriesCount, promptEntriesCount);
        }
    }

    public ArrayList<AuthenticationPromptEntry> getPromptEntries() {
        return promptEntries;
    }

    public void setPromptEntries(ArrayList<AuthenticationPromptEntry> promptEntries) {
        setPromptEntries(promptEntries, false);
    }

    public void setPromptEntries(
            ArrayList<AuthenticationPromptEntry> promptEntries, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPromptEntriesCount(promptEntries.size());
        }
        this.promptEntries = promptEntries;
    }

    public void setSoftlyPromptEntries(
            ArrayList<AuthenticationPromptEntry> promptEntries,
            boolean adjustLengthField,
            Config config) {
        if (config.getAlwaysPrepareAuthentication()
                || this.promptEntries == null
                || this.promptEntries.isEmpty()) {
            this.promptEntries = promptEntries;
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || promptEntriesCount == null
                    || promptEntriesCount.getOriginalValue() == null) {
                setPromptEntriesCount(this.promptEntries.size());
            }
        }
    }

    public void addPromptEntry(AuthenticationPromptEntry promptEntry) {
        addPromptEntry(promptEntry, false);
    }

    public void addPromptEntry(AuthenticationPromptEntry promptEntry, boolean adjustLengthField) {
        promptEntries.add(promptEntry);
        if (adjustLengthField) {
            setPromptEntriesCount(promptEntries.size());
        }
    }

    @Override
    public UserAuthInfoRequestMessageHandler getHandler(SshContext context) {
        return new UserAuthInfoRequestMessageHandler(context, this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (promptEntries != null) {
            holders.addAll(promptEntries);
        }
        return holders;
    }
}
