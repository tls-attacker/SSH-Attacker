/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestLinkSetStatMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class SftpRequestLinkSetStatMessage
        extends SftpRequestExtendedWithPathMessage<SftpRequestLinkSetStatMessage> {

    @HoldsModifiableVariable private SftpFileAttributes attributes = new SftpFileAttributes();

    public SftpRequestLinkSetStatMessage() {
        super();
    }

    public SftpRequestLinkSetStatMessage(SftpRequestLinkSetStatMessage other) {
        super(other);
        attributes = other.attributes != null ? other.attributes.createCopy() : null;
    }

    @Override
    public SftpRequestLinkSetStatMessage createCopy() {
        return new SftpRequestLinkSetStatMessage(this);
    }

    public SftpFileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpFileAttributes attributes) {
        this.attributes = attributes;
    }

    @Override
    public SftpRequestLinkSetStatMessageHandler getHandler(SshContext context) {
        return new SftpRequestLinkSetStatMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestLinkSetStatMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (attributes != null) {
            holders.addAll(attributes.getAllModifiableVariableHolders());
        }
        return holders;
    }
}
