/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config.converter;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;

public class WorkflowTraceTypeConverter implements IStringConverter<WorkflowTraceType> {

    @Override
    public WorkflowTraceType convert(String s) {
        try {
            return WorkflowTraceType.valueOf(s);
        } catch (IllegalArgumentException e) {
            throw new ParameterException("Could not parse WorkflowTraceType.");
        }
    }
}
