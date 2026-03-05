/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.constants.ChannelDataType;
import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.data.sftp.common.message.SftpInitMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.message.SftpVersionMessage;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.factory.SshActionFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlAttribute;

public class DynamicReopenChannelAction extends DynamicMessageAction {

    @XmlAttribute(name = "localChannel")
    protected Integer localChannelId;

    public DynamicReopenChannelAction() {
        super();
    }

    public DynamicReopenChannelAction(String connectionAlias) {
        super(connectionAlias);
    }

    public DynamicReopenChannelAction(int localChannelId) {
        super();
        this.localChannelId = localChannelId;
    }

    public DynamicReopenChannelAction(int localChannelId, String connectionAlias) {
        super(connectionAlias);
        this.localChannelId = localChannelId;
    }

    public DynamicReopenChannelAction(DynamicReopenChannelAction other) {
        super(other);
        localChannelId = other.localChannelId;
    }

    @Override
    public DynamicReopenChannelAction createCopy() {
        return new DynamicReopenChannelAction(this);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        SshContext context = state.getSshContext();

        int forLocalChannelId =
                localChannelId != null
                        ? localChannelId
                        : context.getConfig().getChannelDefaults().getLocalChannelId();

        // check whether the channel needs to be reopened
        // this check should prevent that the channel will be closed if the channel is still open
        Channel channelToReopen =
                context.getChannelManager().getChannelByLocalId(forLocalChannelId);
        if (channelToReopen != null
                && channelToReopen.getCloseMessageReceived().getValue()
                && channelToReopen.getChannelType() == ChannelType.SESSION) {
            if (context.isClient()) {
                // send reopen messages acting as client
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                context.getConnection(),
                                ConnectionEndType.CLIENT,
                                new ChannelCloseMessage(forLocalChannelId),
                                new ChannelOpenSessionMessage(forLocalChannelId)));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                context.getConnection(),
                                ConnectionEndType.SERVER,
                                new ChannelOpenConfirmationMessage()));

                if (channelToReopen.getExpectedDataType() == ChannelDataType.SUBSYSTEM_SFTP) {
                    sshActions.add(
                            SshActionFactory.createMessageAction(
                                    context.getConnection(),
                                    ConnectionEndType.CLIENT,
                                    new ChannelRequestSubsystemMessage()));
                    sshActions.add(
                            SshActionFactory.createMessageAction(
                                    context.getConnection(),
                                    ConnectionEndType.SERVER,
                                    new ChannelSuccessMessage()));

                    sshActions.add(
                            SshActionFactory.createMessageAction(
                                    context.getConnection(),
                                    ConnectionEndType.CLIENT,
                                    new SftpInitMessage()));
                    sshActions.add(
                            SshActionFactory.createMessageAction(
                                    context.getConnection(),
                                    ConnectionEndType.SERVER,
                                    new SftpVersionMessage()));
                }
            } else {
                // send reopen messages acting as server
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                context.getConnection(),
                                ConnectionEndType.SERVER,
                                new ChannelCloseMessage(forLocalChannelId),
                                new ChannelOpenSessionMessage(forLocalChannelId)));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                context.getConnection(),
                                ConnectionEndType.CLIENT,
                                new ChannelOpenConfirmationMessage()));
            }
            sshActions.forEach(sshAction -> sshAction.execute(state));
        }

        setExecuted(true);
    }
}
