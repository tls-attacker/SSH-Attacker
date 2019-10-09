package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.handler.DisconnectMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.DisconnectMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class DisconnectMessage extends Message {

    private ModifiableInteger reasonCode;
    private ModifiableString description;
    private ModifiableString languageTag;

    public DisconnectMessage() {
        this.messageID = ModifiableVariableFactory.safelySetValue(this.messageID, MessageIDConstant.SSH_MSG_DISCONNECT.id);
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
    public Handler getHandler(SshContext context) {
        return new DisconnectMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new DisconnectMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
