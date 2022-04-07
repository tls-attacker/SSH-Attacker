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
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenFailureMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ChannelOpenFailureMessage extends ChannelMessage<ChannelOpenFailureMessage> {

    public static final MessageIdConstant ID = MessageIdConstant.SSH_MSG_CHANNEL_OPEN_FAILURE;

    private ModifiableInteger reasonCode;
    private ModifiableInteger reasonLength;
    private ModifiableString reason;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public ChannelOpenFailureMessage() {}

    public ChannelOpenFailureMessage(Integer senderChannel) {
        super(senderChannel);
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
        if (adjustLengthField) {
            setReasonLength(reason.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.reason = reason;
    }

    public void setReason(String reason, boolean adjustLengthField) {
        if (adjustLengthField) {
            setReasonLength(reason.getBytes(StandardCharsets.UTF_8).length);
        }
        this.reason = ModifiableVariableFactory.safelySetValue(this.reason, reason);
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
    public ChannelOpenFailureMessageHandler getHandler(SshContext context) {
        return new ChannelOpenFailureMessageHandler(context, this);
    }
}
