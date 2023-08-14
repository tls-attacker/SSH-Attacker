/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.mitm.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.config.SshDelegateConfig;
import de.rub.nds.sshattacker.core.config.delegate.*;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;

public class MitmCommandConfig extends SshDelegateConfig {

    @ParametersDelegate private final ConfigOutputDelegate configOutputDelegate;
    @ParametersDelegate private final TimeoutDelegate timeoutDelegate;
    @ParametersDelegate private final WorkflowInputDelegate workflowInputDelegate;
    @ParametersDelegate private final WorkflowOutputDelegate workflowOutputDelegate;
    @ParametersDelegate private final WorkflowTypeDelegate workflowTypeDelegate;
    @ParametersDelegate private final MitmDelegate mitmDelegate;
    @ParametersDelegate private final UserKeysPathDelegate userKeysPathDelegate;
    @ParametersDelegate private final HostKeysPathDelegate hostKeysPathDelegate;

    public MitmCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        configOutputDelegate = new ConfigOutputDelegate();
        timeoutDelegate = new TimeoutDelegate();
        workflowInputDelegate = new WorkflowInputDelegate();
        workflowOutputDelegate = new WorkflowOutputDelegate();
        workflowTypeDelegate = new WorkflowTypeDelegate();
        mitmDelegate = new MitmDelegate();
        userKeysPathDelegate = new UserKeysPathDelegate();
        hostKeysPathDelegate = new HostKeysPathDelegate();
        addDelegate(configOutputDelegate);
        addDelegate(timeoutDelegate);
        addDelegate(workflowInputDelegate);
        addDelegate(workflowOutputDelegate);
        addDelegate(workflowTypeDelegate);
        addDelegate(mitmDelegate);
        addDelegate(userKeysPathDelegate);
        addDelegate(hostKeysPathDelegate);
    }

    public String getWorkflowInput() {
        return workflowInputDelegate.getWorkflowInput();
    }

    public String getWorkflowOutput() {
        return workflowOutputDelegate.getWorkflowOutput();
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        if (config.getWorkflowTraceType() == null) {
            config.setWorkflowTraceType(WorkflowTraceType.MITM);
        }
        return config;
    }
}
