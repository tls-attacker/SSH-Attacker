/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.factory;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.sshattacker.core.workflow.action.SshAction;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Create a WorkflowTace based on a Config instance. */
public class WorkflowConfigurationFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Config config;
    RunningModeType mode;

    public WorkflowConfigurationFactory(Config config) {
        this.config = config;
    }

    public WorkflowTrace createWorkflowTrace(
            WorkflowTraceType workflowTraceType, RunningModeType runningMode) {
        WorkflowTrace workflow = new WorkflowTrace();
        List<SshAction> sshActions = new LinkedList<>();

        // TODO: Define more workflows and fix these ones.
        switch (workflowTraceType) {
            case FULL:
                sshActions.add(new SendAction("client", new ServiceRequestMessage()));
                sshActions.add(new ReceiveAction("client"));
                sshActions.add(new SendAction("client", new UserAuthPasswordMessage()));
                sshActions.add(new ReceiveAction("client"));
                sshActions.add(new SendAction("client", new ChannelOpenMessage()));
                sshActions.add(new ReceiveAction("client"));
                sshActions.add(new SendAction("client", new ChannelRequestExecMessage()));
                sshActions.add(new ReceiveAction("client"));
                break;

            case KEYEXCHANGE:
                sshActions.add(new SendAction("client", new VersionExchangeMessage()));
                sshActions.add(new ReceiveAction("client"));
                sshActions.add(new SendAction("client", new KeyExchangeInitMessage()));
                sshActions.add(new ReceiveAction("client"));
                sshActions.add(new SendAction("client", new EcdhKeyExchangeInitMessage()));
                sshActions.add(new ReceiveAction("client"));
                sshActions.add(new SendAction("client", new NewKeysMessage()));
                sshActions.add(new ActivateEncryptionAction());
                break;
        }
        workflow.addSshActions(sshActions);

        return workflow;
    }
}
