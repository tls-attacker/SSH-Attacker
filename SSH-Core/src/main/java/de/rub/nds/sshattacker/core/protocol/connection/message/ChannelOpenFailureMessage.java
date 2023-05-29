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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenFailureMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenFailureMessageSerializer;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class ChannelOpenFailureMessage extends ChannelMessage<ChannelOpenFailureMessage> {

    private ModifiableInteger reasonCode;
    private ModifiableInteger reasonLength;
    private ModifiableString reason;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

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

    @Override
    public ChannelOpenFailureMessageHandler getHandler(SshContext context) {
        return new ChannelOpenFailureMessageHandler(context);
    }

    @Override
    public ChannelOpenFailureMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelOpenFailureMessageParser(stream);
    }

    @Override
    public ChannelOpenFailureMessagePreparator getPreparator(SshContext context) {
        return new ChannelOpenFailureMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelOpenFailureMessageSerializer getSerializer(SshContext context) {
        return new ChannelOpenFailureMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "OPENFAIL";
    }
}
