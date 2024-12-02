/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenFailureMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ChannelOpenFailureMessage extends ChannelMessage<ChannelOpenFailureMessage> {

    private ModifiableInteger reasonCode;
    private ModifiableInteger reasonLength;
    private ModifiableString reason;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public ChannelOpenFailureMessage() {
        super();
    }

    public ChannelOpenFailureMessage(ChannelOpenFailureMessage other) {
        super(other);
        reasonCode = other.reasonCode != null ? other.reasonCode.createCopy() : null;
        reasonLength = other.reasonLength != null ? other.reasonLength.createCopy() : null;
        reason = other.reason != null ? other.reason.createCopy() : null;
        languageTagLength =
                other.languageTagLength != null ? other.languageTagLength.createCopy() : null;
        languageTag = other.languageTag != null ? other.languageTag.createCopy() : null;
    }

    @Override
    public ChannelOpenFailureMessage createCopy() {
        return new ChannelOpenFailureMessage(this);
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

    public ModifiableInteger getReasonLength() {
        return reasonLength;
    }

    public void setReasonLength(ModifiableInteger reasonLength) {
        this.reasonLength = reasonLength;
    }

    public void setReasonLength(int reasonLength) {
        this.reasonLength =
                ModifiableVariableFactory.safelySetValue(this.reasonLength, reasonLength);
    }

    public ModifiableString getReason() {
        return reason;
    }

    public void setReason(ModifiableString reason) {
        setReason(reason, false);
    }

    public void setReason(String reason) {
        setReason(reason, false);
    }

    public void setReason(ModifiableString reason, boolean adjustLengthField) {
        this.reason = reason;
        if (adjustLengthField) {
            setReasonLength(this.reason.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setReason(String reason, boolean adjustLengthField) {
        this.reason = ModifiableVariableFactory.safelySetValue(this.reason, reason);
        if (adjustLengthField) {
            setReasonLength(this.reason.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyReason(String reason, boolean adjustLengthField, Config config) {
        if (this.reason == null || this.reason.getOriginalValue() == null) {
            this.reason = ModifiableVariableFactory.safelySetValue(this.reason, reason);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || reasonLength == null
                    || reasonLength.getOriginalValue() == null) {
                setReasonLength(this.reason.getValue().getBytes(StandardCharsets.UTF_8).length);
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
    public ChannelOpenFailureMessageHandler getHandler(SshContext context) {
        return new ChannelOpenFailureMessageHandler(context, this);
    }
}
