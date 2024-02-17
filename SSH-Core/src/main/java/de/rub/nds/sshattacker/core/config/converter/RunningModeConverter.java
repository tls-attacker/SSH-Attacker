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
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import java.util.Arrays;

/** Converts a string to a RunningModeType (for command line purposes). */
public class RunningModeConverter implements IStringConverter<RunningModeType> {

    @Override
    public RunningModeType convert(String s) {

        try {
            return RunningModeType.valueOf(s);
        } catch (IllegalArgumentException e) {
            throw new ParameterException(
                    "Value "
                            + s
                            + " cannot be converted to a RunningModeType. "
                            + "Available values are: "
                            + Arrays.toString(RunningModeType.values()));
        }
    }
}
