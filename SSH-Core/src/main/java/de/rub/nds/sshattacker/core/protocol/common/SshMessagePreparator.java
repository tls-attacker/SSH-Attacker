/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.constants.SshMessageConstants;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SshMessagePreparator<T extends SshMessage<T>>
        extends ProtocolMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SshMessagePreparator(Chooser chooser, T message) {
        super(chooser, message);
    }

    @Override
    protected final void prepareProtocolMessageContents() {
        prepareMessageId();
        prepareMessageSpecificContents();
    }

    private void prepareMessageId() {
        try {
            MessageIdConstant messageId =
                    (MessageIdConstant)
                            getObject()
                                    .getClass()
                                    .getField(SshMessageConstants.CLASS_ID_FIELD)
                                    .get(null);
            getObject().setMessageId(messageId);
        } catch (NoSuchFieldException e) {
            LOGGER.fatal(
                    "Unable to instantiate SSH message of type {}, no ID field found - make sure this class or one of its super classes offers a static ID field containing the corresponding message id constant",
                    getObject().toCompactString());
            LOGGER.debug(e);
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            LOGGER.fatal(
                    "Unable to instantiate SSH message of type {}, unable to access ID field - make sure it is static and publicly available",
                    getObject().toCompactString());
            LOGGER.debug(e);
            throw new RuntimeException(e);
        } catch (ClassCastException e) {
            LOGGER.fatal(
                    "Unable to instantiate SSH message of type {}, unable to cast ID field to {} - make sure the type of the ID field is correct",
                    getObject().toCompactString(),
                    MessageIdConstant.class.getSimpleName());
            LOGGER.debug(e);
            throw new RuntimeException(e);
        }
    }

    public abstract void prepareMessageSpecificContents();
}
