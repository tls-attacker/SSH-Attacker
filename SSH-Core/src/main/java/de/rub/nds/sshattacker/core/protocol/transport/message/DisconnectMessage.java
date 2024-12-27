/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DisconnectMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class DisconnectMessage extends SshMessage<DisconnectMessage> {

    private ModifiableInteger reasonCode;
    private ModifiableInteger descriptionLength;
    private ModifiableString description;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public DisconnectMessage() {
        super();
    }

    public DisconnectMessage(DisconnectMessage other) {
        super(other);
        reasonCode = other.reasonCode != null ? other.reasonCode.createCopy() : null;
        descriptionLength =
                other.descriptionLength != null ? other.descriptionLength.createCopy() : null;
        description = other.description != null ? other.description.createCopy() : null;
        languageTagLength =
                other.languageTagLength != null ? other.languageTagLength.createCopy() : null;
        languageTag = other.languageTag != null ? other.languageTag.createCopy() : null;
    }

    @Override
    public DisconnectMessage createCopy() {
        return new DisconnectMessage(this);
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

    public void setSoftlyReasonCode(int reasonCode) {
        if (this.reasonCode == null || this.reasonCode.getOriginalValue() == null) {
            this.reasonCode = ModifiableVariableFactory.safelySetValue(this.reasonCode, reasonCode);
        }
    }

    public void setReasonCode(DisconnectReason reason) {
        setReasonCode(reason.getId());
    }

    public void setSoftlyReasonCode(DisconnectReason reason) {
        setSoftlyReasonCode(reason.getId());
    }

    public ModifiableInteger getDescriptionLength() {
        return descriptionLength;
    }

    public void setDescriptionLength(ModifiableInteger descriptionLength) {
        this.descriptionLength = descriptionLength;
    }

    public void setDescriptionLength(int descriptionLength) {
        this.descriptionLength =
                ModifiableVariableFactory.safelySetValue(this.descriptionLength, descriptionLength);
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
        this.description = description;
        if (adjustLengthField) {
            setDescriptionLength(
                    this.description.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setDescription(String description, boolean adjustLengthField) {
        this.description = ModifiableVariableFactory.safelySetValue(this.description, description);
        if (adjustLengthField) {
            setDescriptionLength(
                    this.description.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyDescription(String description, boolean adjustLengthField, Config config) {
        if (this.description == null || this.description.getOriginalValue() == null) {
            this.description =
                    ModifiableVariableFactory.safelySetValue(this.description, description);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || descriptionLength == null
                    || descriptionLength.getOriginalValue() == null) {
                setDescriptionLength(
                        this.description.getValue().getBytes(StandardCharsets.UTF_8).length);
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

    @Override
    public DisconnectMessageHandler getHandler(SshContext context) {
        return new DisconnectMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        DisconnectMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
