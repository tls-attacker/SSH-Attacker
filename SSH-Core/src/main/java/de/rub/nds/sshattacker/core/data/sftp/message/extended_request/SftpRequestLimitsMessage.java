/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestLimitsMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestLimitsMessage extends SftpRequestExtendedMessage<SftpRequestLimitsMessage> {

    public SftpRequestLimitsMessage() {
        super();
    }

    public SftpRequestLimitsMessage(SftpRequestLimitsMessage other) {
        super(other);
    }

    @Override
    public SftpRequestLimitsMessage createCopy() {
        return new SftpRequestLimitsMessage(this);
    }

    @Override
    public SftpRequestLimitsMessageHandler getHandler(SshContext context) {
        return new SftpRequestLimitsMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestLimitsMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestLimitsMessageHandler.SERIALIZER.serialize(this);
    }
}
