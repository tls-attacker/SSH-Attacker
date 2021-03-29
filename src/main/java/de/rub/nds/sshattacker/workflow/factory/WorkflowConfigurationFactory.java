/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.workflow.factory;

import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.constants.RunningModeType;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.protocol.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;
import de.rub.nds.sshattacker.protocol.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.protocol.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.workflow.action.ActivateEncryptionAction;
import de.rub.nds.sshattacker.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.workflow.action.SendAction;
import de.rub.nds.sshattacker.workflow.action.SshAction;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Create a WorkflowTace based on a Config instance.
 */
public class WorkflowConfigurationFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Config config;
    RunningModeType mode;

    public WorkflowConfigurationFactory(Config config) {
        this.config = config;
    }

    public WorkflowTrace createWorkflowTrace(WorkflowTraceType workflowTraceType, RunningModeType runningMode) {
        WorkflowTrace workflow = new WorkflowTrace();
        List<SshAction> sshActions = new LinkedList<>();

        switch (workflowTraceType) {
            case FULL:
                sshActions.add(new SendAction(new ServiceRequestMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new UserAuthPasswordMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new ChannelOpenMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new ChannelRequestMessage()));
                sshActions.add(new ReceiveAction());
                break;

            case KEYEXCHANGE:
                sshActions.add(new SendAction(new ClientInitMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new KeyExchangeInitMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new EcdhKeyExchangeInitMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new NewKeysMessage()));
                sshActions.add(new ActivateEncryptionAction());
                break;

        }
        workflow.addSshActions(sshActions);

        return workflow;
    }
}
