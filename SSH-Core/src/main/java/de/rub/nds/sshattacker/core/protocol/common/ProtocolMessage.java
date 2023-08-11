/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.DataContainer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlTransient;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Random;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class ProtocolMessage<Self extends ProtocolMessage<?>>
        extends ModifiableVariableHolder implements DataContainer<Self, SshContext> {

    /** content type */
    @XmlTransient protected final boolean GOING_TO_BE_SENT_DEFAULT = true;

    @XmlTransient protected final boolean REQUIRED_DEFAULT = true;

    @XmlTransient protected final boolean ADJUST_CONTEXT_DEFAULT = true;

    /** Defines whether this message is necessarily required in the workflow. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean required;
    /**
     * Defines if the message should be sent during the workflow. Using this flag it is possible to
     * omit a message is sent during the handshake while it is executed to initialize specific
     * variables.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean goingToBeSent;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean adjustContext;

    /** resulting message */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    protected ModifiableByteArray completeResultingMessage;

    public MessageIdConstant getMessageIdConstant() {
        return messageIdConstant;
    }

    public void setMessageIdConstant(MessageIdConstant MessageIdConstant) {
        this.messageIdConstant = MessageIdConstant;
    }

    /** content type */
    @XmlTransient protected MessageIdConstant messageIdConstant;

    public ProtocolMessage() {}

    public boolean isRequired() {
        if (required == null || required.getValue() == null) {
            return REQUIRED_DEFAULT;
        }
        return required.getValue();
    }

    public void setRequired(boolean required) {
        this.required = ModifiableVariableFactory.safelySetValue(this.required, required);
    }

    public boolean isGoingToBeSent() {
        if (goingToBeSent == null || goingToBeSent.getValue() == null) {
            return GOING_TO_BE_SENT_DEFAULT;
        }
        return goingToBeSent.getValue();
    }

    public void setGoingToBeSent(boolean goingToBeSent) {
        this.goingToBeSent =
                ModifiableVariableFactory.safelySetValue(this.goingToBeSent, goingToBeSent);
    }

    public void setGoingToBeSent(ModifiableBoolean goingToBeSent) {
        this.goingToBeSent = goingToBeSent;
    }

    @Override
    public Field getRandomModifiableVariableField(Random random) {
        List<Field> fields = getAllModifiableVariableFields();
        int randomField = random.nextInt(fields.size());
        return fields.get(randomField);
    }

    public ModifiableByteArray getCompleteResultingMessage() {
        return completeResultingMessage;
    }

    public void setCompleteResultingMessage(ModifiableByteArray completeResultingMessage) {
        this.completeResultingMessage = completeResultingMessage;
    }

    public void setCompleteResultingMessage(byte[] completeResultingMessage) {
        this.completeResultingMessage =
                ModifiableVariableFactory.safelySetValue(
                        this.completeResultingMessage, completeResultingMessage);
    }

    public boolean getAdjustContext() {
        if (adjustContext == null || adjustContext.getValue() == null) {
            return ADJUST_CONTEXT_DEFAULT;
        }
        return adjustContext.getValue();
    }

    public void setAdjustContext(ModifiableBoolean adjustContext) {
        this.adjustContext = adjustContext;
    }

    public void setAdjustContext(Boolean adjustContext) {
        this.adjustContext =
                ModifiableVariableFactory.safelySetValue(this.adjustContext, adjustContext);
    }

    @Override
    public abstract ProtocolMessageHandler<Self> getHandler(SshContext sshContext);

    // @Override
    // public abstract ProtocolMessageParser<Self> getParser(byte[] array);

    // @Override
    // public abstract ProtocolMessageParser<Self> getParser(byte[] array, int startPosition);

    @Override
    public abstract ProtocolMessagePreparator<Self> getPreparator(SshContext sshContext);

    @Override
    public abstract ProtocolMessageSerializer<Self> getSerializer(SshContext sshContext);

    public abstract String toCompactString();
}
