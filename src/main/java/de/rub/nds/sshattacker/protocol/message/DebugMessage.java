package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.state.SshContext;

public class DebugMessage extends Message {

    private ModifiableByte alwaysDisplay;
    private ModifiableInteger messageLength;
    private ModifiableString message;
    private ModifiableInteger languageTagLength;
    private ModifiableString languageTag;

    public ModifiableByte getAlwaysDisplay() {
        return alwaysDisplay;
    }

    public void setAlwaysDisplay(ModifiableByte alwaysDisplay) {
        this.alwaysDisplay = alwaysDisplay;
    }

    public void setAlwaysDisplay(byte alwaysDisplay) {
        this.alwaysDisplay = ModifiableVariableFactory.safelySetValue(this.alwaysDisplay, alwaysDisplay);
    }

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(int messageLength) {
        this.messageLength = ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
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

    public ModifiableInteger getLanguageTagLength() {
        return languageTagLength;
    }

    public void setLanguageTagLength(ModifiableInteger languageTagLength) {
        this.languageTagLength = languageTagLength;
    }

    public void setLanguageTagLength(int languageTagLength) {
        this.languageTagLength = ModifiableVariableFactory.safelySetValue(this.languageTagLength, languageTagLength);
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
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Serializer getSerializer() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
