/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.VersionExchangeMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.VersionExchangeMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.VersionExchangeMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.VersionExchangeMessageSerializer;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionExchangeMessage extends ProtocolMessage<VersionExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private ModifiableString version;
    private ModifiableString comment;
    private ModifiableString endOfMessageSequence;

    public ModifiableString getVersion() {
        return version;
    }

    public void setVersion(ModifiableString version) {
        this.version = version;
    }

    public void setVersion(String version) {
        this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
    }

    public ModifiableString getComment() {
        return comment;
    }

    public void setComment(ModifiableString comment) {
        this.comment = comment;
    }

    public void setComment(String comment) {
        this.comment = ModifiableVariableFactory.safelySetValue(this.comment, comment);
    }

    public String getIdentification() {
        if (comment.getValue().isEmpty()) return version.getValue();
        return version.getValue() + CharConstants.VERSION_COMMENT_SEPARATOR + comment.getValue();
    }

    public ModifiableString getEndOfMessageSequence() {
        return endOfMessageSequence;
    }

    public void setEndOfMessageSequence(ModifiableString endOfMessageSequence) {
        this.endOfMessageSequence = endOfMessageSequence;
    }

    public void setEndOfMessageSequence(String endOfMessageSequence) {
        this.endOfMessageSequence =
                ModifiableVariableFactory.safelySetValue(
                        this.endOfMessageSequence, endOfMessageSequence);
    }

    @Override
    public VersionExchangeMessageHandler getHandler(SshContext context) {
        return new VersionExchangeMessageHandler(context);
    }

    @Override
    public String toCompactString() {
        return getClass().getSimpleName();
    }

    @Override
    public VersionExchangeMessageParser getParser(SshContext context, InputStream stream) {
        return new VersionExchangeMessageParser(stream);
    }

    @Override
    public VersionExchangeMessagePreparator getPreparator(SshContext context) {
        return new VersionExchangeMessagePreparator(context.getChooser(), this);
    }

    @Override
    public VersionExchangeMessageSerializer getSerializer(SshContext context) {
        LOGGER.debug("[bro] getting serializer");
        return new VersionExchangeMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "VERSION_EXCHANGE";
    }
}
