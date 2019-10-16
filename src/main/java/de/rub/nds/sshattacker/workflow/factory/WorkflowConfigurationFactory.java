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
import de.rub.nds.sshattacker.protocol.message.UserauthPasswordMessage;
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

        switch (workflowTraceType) {
            case FULL:
                List<SshAction> sshActions = new LinkedList<>();
                sshActions.add(new SendAction(new ClientInitMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new KeyExchangeInitMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new EcdhKeyExchangeInitMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new NewKeysMessage()));
                sshActions.add(new ActivateEncryptionAction());
                sshActions.add(new SendAction(new ServiceRequestMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new UserauthPasswordMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new ChannelOpenMessage()));
                sshActions.add(new ReceiveAction());
                sshActions.add(new SendAction(new ChannelRequestMessage()));
                sshActions.add(new ReceiveAction());

                workflow.addSshActions(sshActions);
        }
        return workflow;
    }
}
