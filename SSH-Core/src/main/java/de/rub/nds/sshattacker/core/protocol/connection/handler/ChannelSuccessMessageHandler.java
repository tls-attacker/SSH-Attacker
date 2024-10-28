/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.constants.ChannelDataType;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelSuccessMessageHandler extends SshMessageHandler<ChannelSuccessMessage> {

    public ChannelSuccessMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelSuccessMessageHandler(SshContext context, ChannelSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        Integer recipientChannelId = message.getRecipientChannelId().getValue();
        Channel channel = context.getChannelManager().getChannelByLocalId(recipientChannelId);
        if (channel != null) {
            ChannelRequestMessage<?> requestMessage = channel.removeFirstSentRequestThatWantReply();
            if (requestMessage != null) {
                // Set the expected ChannelDataType corresponding to the request
                ChannelDataType newDataTyp = ChannelDataType.UNSET;
                switch (ChannelRequestType.fromName(requestMessage.getRequestType().getValue())) {
                    case PTY_REQ:
                        newDataTyp = ChannelDataType.PTY;
                        break;
                    case SHELL:
                    case EXEC:
                        newDataTyp = ChannelDataType.SHELL;
                        break;
                    case SUBSYSTEM:
                        if (((ChannelRequestSubsystemMessage) requestMessage)
                                .getSubsystemName()
                                .getValue()
                                .equals("sftp")) {
                            newDataTyp = ChannelDataType.SUBSYSTEM_SFTP;
                        } else {
                            newDataTyp = ChannelDataType.SUBSYSTEM_UNKNOWN;
                        }

                        break;
                    default:
                        break;
                }
                if (newDataTyp != ChannelDataType.UNSET) {
                    ChannelDataType currentDataType = channel.getExpectedDataType();
                    if (currentDataType == ChannelDataType.UNSET) {
                        channel.setExpectedDataType(newDataTyp);
                    } else if (currentDataType != newDataTyp) {
                        channel.setExpectedDataType(ChannelDataType.UNKNOWN);
                    }
                }
            } else {
                LOGGER.warn(
                        "{} received but no channel request was send before on channel with id {}.",
                        message.getClass().getSimpleName(),
                        message.getRecipientChannelId().getValue());
            }
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring it.",
                    message.getClass().getSimpleName(),
                    message.getRecipientChannelId().getValue());
        }
    }

    @Override
    public SshMessageParser<ChannelSuccessMessage> getParser(byte[] array) {
        return new ChannelSuccessMessageParser(array);
    }

    @Override
    public SshMessageParser<ChannelSuccessMessage> getParser(byte[] array, int startPosition) {
        return new ChannelSuccessMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<ChannelSuccessMessage> getPreparator() {
        return new ChannelSuccessMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<ChannelSuccessMessage> getSerializer() {
        return new ChannelMessageSerializer<>(message);
    }
}
