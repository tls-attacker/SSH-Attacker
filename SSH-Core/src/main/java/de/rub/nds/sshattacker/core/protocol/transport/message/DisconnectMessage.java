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
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DisconnectMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DisconnectMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DisconnectMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DisconnectMessage extends Message<DisconnectMessage> {

    private ModifiableInteger reasonCode;
    private ModifiableString description;
    private ModifiableString languageTag;

    public DisconnectMessage() {
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

    public ModifiableString getDescription() {
        return description;
    }

    public void setDescription(ModifiableString description) {
        this.description = description;
    }

    public void setDescription(String description) {
        this.description = ModifiableVariableFactory.safelySetValue(this.description, description);
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
