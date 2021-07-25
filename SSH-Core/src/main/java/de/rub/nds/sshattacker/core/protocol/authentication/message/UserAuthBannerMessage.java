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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthBannerMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthBannerMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthBannerMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.nio.charset.StandardCharsets;

public class UserAuthBannerMessage extends Message<UserAuthBannerMessage> {

    private ModifiableInteger messageLength;
    private ModifiableString message;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public UserAuthBannerMessage() {
        super(MessageIDConstant.SSH_MSG_USERAUTH_BANNER);
    }

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public ModifiableString getMessage() {
        return message;
    }

    public ModifiableInteger getLanguageTagLength() {
        return languageTagLength;
    }

    public ModifiableString getLanguageTag() {
        return languageTag;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(int messageLength) {
        this.messageLength = ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
    }

    public void setMessage(ModifiableString message) {
        setMessage(message, true);
    }

    public void setMessage(String message) {
        setMessage(message, true);
    }

    public void setMessage(ModifiableString message, boolean adjustLengthField) {
        if (adjustLengthField) {
            setMessageLength(message.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.message = message;
    }

    public void setMessage(String message, boolean adjustLengthField) {
        if (adjustLengthField) {
            setMessageLength(message.getBytes(StandardCharsets.UTF_8).length);
        }
        this.message = ModifiableVariableFactory.safelySetValue(this.message, message);
    }

    public void setLanguageTagLength(ModifiableInteger languageTagLength) {
        this.languageTagLength = languageTagLength;
    }

    public void setLanguageTagLength(int languageTagLength) {
        this.languageTagLength = ModifiableVariableFactory.safelySetValue(this.languageTagLength, languageTagLength);
    }

    public void setLanguageTag(ModifiableString languageTag) {
        setLanguageTag(languageTag, true);
    }

    public void setLanguageTag(String languageTag) {
        setLanguageTag(languageTag, true);
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
