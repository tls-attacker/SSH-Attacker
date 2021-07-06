/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.preparator.ChannelOpenFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.serializer.ChannelOpenFailureMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.handler.ChannelOpenFailureMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenFailureMessage extends Message<ChannelOpenFailureMessage> {

    private ModifiableInteger recipientChannel;
    private ModifiableInteger reasonCode;
    private ModifiableString reason;
    private ModifiableString languageTag;

    public ModifiableInteger getRecipientChannel() {
        return recipientChannel;
    }

    public void setRecipientChannel(ModifiableInteger recipientChannel) {
        this.recipientChannel = recipientChannel;
    }

    public void setRecipientChannel(int recipientChannel) {
        this.recipientChannel = ModifiableVariableFactory.safelySetValue(this.recipientChannel, recipientChannel);
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

    public ModifiableString getReason() {
        return reason;
    }

    public void setReason(ModifiableString reason) {
        this.reason = reason;
    }

    public void setReason(String reason) {
        this.reason = ModifiableVariableFactory.safelySetValue(this.reason, reason);
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

    @Override
    public ChannelOpenFailureMessageHandler getHandler(SshContext context) {
        return new ChannelOpenFailureMessageHandler(context);
    }

    @Override
    public ChannelOpenFailureMessageSerializer getSerializer() {
        return new ChannelOpenFailureMessageSerializer(this);
    }

    @Override
    public ChannelOpenFailureMessagePreparator getPreparator(SshContext context) {
        return new ChannelOpenFailureMessagePreparator(context, this);
    }

}
