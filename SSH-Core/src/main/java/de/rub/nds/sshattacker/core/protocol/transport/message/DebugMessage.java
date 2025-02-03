/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DebugMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class DebugMessage extends SshMessage<DebugMessage> {

    private ModifiableByte alwaysDisplay;
    private ModifiableInteger messageLength;
    private ModifiableString message;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public DebugMessage() {
        super();
    }

    public DebugMessage(DebugMessage other) {
        super(other);
        alwaysDisplay = other.alwaysDisplay != null ? other.alwaysDisplay.createCopy() : null;
        messageLength = other.messageLength != null ? other.messageLength.createCopy() : null;
        message = other.message != null ? other.message.createCopy() : null;
        languageTagLength =
                other.languageTagLength != null ? other.languageTagLength.createCopy() : null;
        languageTag = other.languageTag != null ? other.languageTag.createCopy() : null;
    }

    @Override
    public DebugMessage createCopy() {
        return new DebugMessage(this);
    }

    public ModifiableByte getAlwaysDisplay() {
        return alwaysDisplay;
    }

    public void setAlwaysDisplay(ModifiableByte alwaysDisplay) {
        this.alwaysDisplay = alwaysDisplay;
    }

    public void setAlwaysDisplay(byte alwaysDisplay) {
        this.alwaysDisplay =
                ModifiableVariableFactory.safelySetValue(this.alwaysDisplay, alwaysDisplay);
    }

    public void setSoftlyAlwaysDisplay(byte alwaysDisplay) {
        this.alwaysDisplay =
                ModifiableVariableFactory.softlySetValue(this.alwaysDisplay, alwaysDisplay);
    }

    public void setAlwaysDisplay(boolean alwaysDisplay) {
        setAlwaysDisplay(Converter.booleanToByte(alwaysDisplay));
    }

    public void setSoftlyAlwaysDisplay(boolean alwaysDisplay) {
        setSoftlyAlwaysDisplay(Converter.booleanToByte(alwaysDisplay));
    }

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

    public void setSoftlyMessage(String message, boolean adjustLengthField, Config config) {
        this.message = ModifiableVariableFactory.softlySetValue(this.message, message);
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || messageLength == null
                    || messageLength.getOriginalValue() == null) {
                setMessageLength(this.message.getValue().getBytes(StandardCharsets.UTF_8).length);
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
        this.languageTag = ModifiableVariableFactory.softlySetValue(this.languageTag, languageTag);
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || languageTagLength == null
                    || languageTagLength.getOriginalValue() == null) {
                setLanguageTagLength(
                        this.languageTag.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
    }

    public static final DebugMessageHandler HANDLER = new DebugMessageHandler();

    @Override
    public DebugMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        DebugMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return DebugMessageHandler.SERIALIZER.serialize(this);
    }
}
