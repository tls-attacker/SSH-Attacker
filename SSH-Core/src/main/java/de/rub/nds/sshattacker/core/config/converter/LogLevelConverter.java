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

import org.apache.logging.log4j.Level;

import java.util.Arrays;

/** Converts a log level string to an Apache log4j Level object (for command line purposes). */
public class LogLevelConverter implements IStringConverter<Level> {

    @Override
    public Level convert(String s) {
        Level level = Level.toLevel(s);
        if (level == null) {
            throw new ParameterException(
                    "Value "
                            + s
                            + " cannot be converted to a log4j level. "
                            + "Available values are: "
                            + Arrays.toString(Level.values()));
        }

        return level;
    }
}
