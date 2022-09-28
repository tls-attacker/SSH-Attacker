/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.constants.SshMessageConstants;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlType(namespace = "ssh-attacker")
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class SshMessage<T extends SshMessage<T>> extends ProtocolMessage<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ModifiableByte messageId;

    protected SshMessage() {
        try {
            MessageIdConstant messageId =
                    (MessageIdConstant)
                            this.getClass().getField(SshMessageConstants.CLASS_ID_FIELD).get(null);
            this.setMessageId(messageId);
        } catch (NoSuchFieldException e) {
            LOGGER.fatal(
                    "Unable to instantiate SSH message of type {}, no ID field found - make sure this class or one of its super classes offers a static ID field containing the corresponding message id constant",
                    this.toCompactString());
            LOGGER.debug(e);
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            LOGGER.fatal(
                    "Unable to instantiate SSH message of type {}, unable to access ID field - make sure it is static and publicly available",
                    this.toCompactString());
            LOGGER.debug(e);
            throw new RuntimeException(e);
        } catch (ClassCastException e) {
            LOGGER.fatal(
                    "Unable to instantiate SSH message of type {}, unable to cast ID field to {} - make sure the type of the ID field is correct",
                    this.toCompactString(),
                    MessageIdConstant.class.getSimpleName());
            LOGGER.debug(e);
            throw new RuntimeException(e);
        }
    }

    public ModifiableByte getMessageId() {
        return messageId;
    }

    public void setMessageId(ModifiableByte messageId) {
        this.messageId = messageId;
    }

    public void setMessageId(byte messageId) {
        this.messageId = ModifiableVariableFactory.safelySetValue(this.messageId, messageId);
    }

    public void setMessageId(MessageIdConstant messageId) {
        setMessageId(messageId.getId());
    }

    @Override
    public abstract SshMessageHandler<T> getHandler(SshContext context);

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }
}
