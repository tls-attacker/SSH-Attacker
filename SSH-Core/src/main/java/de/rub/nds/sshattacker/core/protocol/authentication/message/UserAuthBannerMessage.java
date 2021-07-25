/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthBannerMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthBannerMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthBannerMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthBannerMessage extends Message<UserAuthBannerMessage> {

    private ModifiableString message;
    private ModifiableString languageTag;

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
    public UserAuthBannerMessageHandler getHandler(SshContext context) {
        return new UserAuthBannerMessageHandler(context);
    }

    @Override
    public UserAuthBannerMessageSerializer getSerializer() {
        return new UserAuthBannerMessageSerializer(this);
    }

    @Override
    public UserAuthBannerMessagePreparator getPreparator(SshContext context) {
        return new UserAuthBannerMessagePreparator(context, this);
    }

}
