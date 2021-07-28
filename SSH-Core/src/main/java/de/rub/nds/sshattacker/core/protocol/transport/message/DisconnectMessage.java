/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DisconnectMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DisconnectMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DisconnectMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.nio.charset.StandardCharsets;

public class DisconnectMessage extends Message<DisconnectMessage> {

    private ModifiableInteger reasonCode;
    private ModifiableInteger descriptionLength;
    private ModifiableString description;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public DisconnectMessage() {
        super(MessageIDConstant.SSH_MSG_DISCONNECT);
    }

    public ModifiableInteger getReasonCode() {
        return reasonCode;
    }

    public void setReasonCode(ModifiableInteger reasonCode) {
        this.reasonCode = reasonCode;
    }

    public void setReasonCode(int reasonCode) {
        this.reasonCode = ModifiableVariableFactory.safelySetValue(this.reasonCode, reasonCode);
    }

    public void setReasonCode(DisconnectReason reason) {
        setReasonCode(reason.id);
    }

    public ModifiableInteger getDescriptionLength() {
        return descriptionLength;
    }

    public void setDescriptionLength(ModifiableInteger descriptionLength) {
        this.descriptionLength = descriptionLength;
    }

    public void setDescriptionLength(int descriptionLength) {
        this.descriptionLength = ModifiableVariableFactory.safelySetValue(this.descriptionLength, descriptionLength);
    }

    public ModifiableString getDescription() {
        return description;
    }

    public void setDescription(ModifiableString description) {
        setDescription(description, false);
    }

    public void setDescription(String description) {
        setDescription(description, false);
    }

    public void setDescription(ModifiableString description, boolean adjustLengthField) {
        if (adjustLengthField) {
            setDescriptionLength(description.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.description = description;
    }

    public void setDescription(String description, boolean adjustLengthField) {
        if (adjustLengthField) {
            setDescriptionLength(description.getBytes(StandardCharsets.UTF_8).length);
        }
        this.description = ModifiableVariableFactory.safelySetValue(this.description, description);
    }

    public ModifiableInteger getLanguageTagLength() {
        return languageTagLength;
    }

    public void setLanguageTagLength(ModifiableInteger languageTagLength) {
        this.languageTagLength = languageTagLength;
    }

    public void setLanguageTagLength(int languageTagLength) {
        this.languageTagLength = ModifiableVariableFactory.safelySetValue(this.languageTagLength, languageTagLength);
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
    public DisconnectMessageHandler getHandler(SshContext context) {
        return new DisconnectMessageHandler(context);
    }

    @Override
    public DisconnectMessageSerializer getSerializer() {
        return new DisconnectMessageSerializer(this);
    }

    @Override
    public DisconnectMessagePreparator getPreparator(SshContext context) {
        return new DisconnectMessagePreparator(context, this);
    }
}
