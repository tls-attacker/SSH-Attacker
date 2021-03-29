package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.UserAuthBannerMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.preparator.UserAuthBannerMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.protocol.serializer.UserAuthBannerMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthBannerMessage extends Message {

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
    public Handler getHandler(SshContext context) {
        return new UserAuthBannerMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new UserAuthBannerMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new UserAuthBannerMessagePreparator(context, this);
    }

}
