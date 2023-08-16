/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.VersionExchangeMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.VersionExchangeMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.VersionExchangeMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.VersionExchangeMessageSSHV1Serializer;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionExchangeMessageSSHV1 extends ProtocolMessage<VersionExchangeMessageSSHV1> {

    private static final Logger LOGGER = LogManager.getLogger();

    private ModifiableString version;
    private ModifiableString comment;
    private ModifiableString endOfMessageSequence;
    MessageIdConstant messageIdConstant;

    public VersionExchangeMessageSSHV1() {
        super();
        this.messageIdConstant = MessageIdConstant.VERSION_EXCHANGE_MESSAGE;
    }

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
    public VersionExchangeMessageSSHV1Handler getHandler(SshContext context) {
        return new VersionExchangeMessageSSHV1Handler(context);
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }

    @Override
    public VersionExchangeMessageSSHV1Parser getParser(SshContext context, InputStream stream) {
        return new VersionExchangeMessageSSHV1Parser(stream);
    }

    @Override
    public VersionExchangeMessageSSHV1Preparator getPreparator(SshContext context) {
        return new VersionExchangeMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public VersionExchangeMessageSSHV1Serializer getSerializer(SshContext context) {
        LOGGER.debug("[bro] getting serializer");
        return new VersionExchangeMessageSSHV1Serializer(this);
    }

    @Override
    public String toShortString() {
        return "VESION_EXCHANGE";
    }
}
