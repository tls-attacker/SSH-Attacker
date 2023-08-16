/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthBannerMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthBannerMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthBannerMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthBannerMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class UserAuthBannerMessage extends SshMessage<UserAuthBannerMessage> {

    private ModifiableInteger messageLength;
    private ModifiableString message;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(int messageLength) {
        this.messageLength =
                ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
    }

    public ModifiableString getMessage() {
        return message;
    }

    public void setMessage(ModifiableString message) {
        setMessage(message, false);
    }

    public void setMessage(String message) {
        setMessage(message, false);
    }

    public void setMessage(byte[] message) {
        setMessage(new String(message, StandardCharsets.UTF_8), false);
    }

    public void setMessage(ModifiableString message, boolean adjustLengthField) {
        this.message = message;
        if (adjustLengthField) {
            setMessageLength(this.message.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setMessage(String message, boolean adjustLengthField) {
        this.message = ModifiableVariableFactory.safelySetValue(this.message, message);
        if (adjustLengthField) {
            setMessageLength(this.message.getValue().getBytes(StandardCharsets.UTF_8).length);
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
    public UserAuthBannerMessageHandler getHandler(SshContext context) {
        return new UserAuthBannerMessageHandler(context);
    }

    @Override
    public UserAuthBannerMessagePreparator getPreparator(SshContext sshContext) {
        return new UserAuthBannerMessagePreparator(sshContext.getChooser(), this);
    }

    @Override
    public UserAuthBannerMessageSerializer getSerializer(SshContext sshContext) {
        return new UserAuthBannerMessageSerializer(this);
    }

    @Override
    public UserAuthBannerMessageParser getParser(SshContext sshContext, InputStream stream) {
        return new UserAuthBannerMessageParser(stream);
    }

    @Override
    public String toShortString() {
        return "USERAUTH_BANNER";
    }
}
