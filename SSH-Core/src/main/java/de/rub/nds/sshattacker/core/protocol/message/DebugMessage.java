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
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.preparator.DebugMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.serializer.DebugMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.handler.DebugMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DebugMessage extends Message<DebugMessage> {

    private ModifiableBoolean alwaysDisplay;
    private ModifiableString message;
    private ModifiableString languageTag;

    public ModifiableBoolean getAlwaysDisplay() {
        return alwaysDisplay;
    }

    public void setAlwaysDisplay(ModifiableBoolean alwaysDisplay) {
        this.alwaysDisplay = alwaysDisplay;
    }

    public void setAlwaysDisplay(boolean alwaysDisplay) {
        this.alwaysDisplay = ModifiableVariableFactory.safelySetValue(this.alwaysDisplay, alwaysDisplay);
    }

    public ModifiableString getMessage() {
        return message;
    }

    public void setMessage(ModifiableString message) {
        this.message = message;
    }

    public void setMessage(String message) {
        this.message = ModifiableVariableFactory.safelySetValue(this.message, message);
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
    public DebugMessageHandler getHandler(SshContext context) {
        return new DebugMessageHandler(context);
    }

    @Override
    public DebugMessageSerializer getSerializer() {
        return new DebugMessageSerializer(this);
    }

    @Override
    public DebugMessagePreparator getPreparator(SshContext context) {
        return new DebugMessagePreparator(context, this);
    }

}
