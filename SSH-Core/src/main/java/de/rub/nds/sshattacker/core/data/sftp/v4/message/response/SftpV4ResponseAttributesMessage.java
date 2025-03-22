/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.message.response;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.data.sftp.common.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.handler.response.SftpV4ResponseAttributesMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class SftpV4ResponseAttributesMessage
        extends SftpResponseMessage<SftpV4ResponseAttributesMessage> {

    @HoldsModifiableVariable private SftpV4FileAttributes attributes = new SftpV4FileAttributes();

    public SftpV4ResponseAttributesMessage() {
        super();
    }

    public SftpV4ResponseAttributesMessage(SftpV4ResponseAttributesMessage other) {
        super(other);
        attributes = other.attributes != null ? other.attributes.createCopy() : null;
    }

    @Override
    public SftpV4ResponseAttributesMessage createCopy() {
        return new SftpV4ResponseAttributesMessage(this);
    }

    public SftpV4FileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpV4FileAttributes attributes) {
        this.attributes = attributes;
    }

    public static final SftpV4ResponseAttributesMessageHandler HANDLER =
            new SftpV4ResponseAttributesMessageHandler();

    @Override
    public SftpV4ResponseAttributesMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpV4ResponseAttributesMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpV4ResponseAttributesMessageHandler.SERIALIZER.serialize(this);
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
