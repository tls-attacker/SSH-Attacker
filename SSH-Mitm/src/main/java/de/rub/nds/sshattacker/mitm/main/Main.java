/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.mitm.main;

import com.beust.jcommander.ParameterException;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

public class Main {

    // Loosely based on sysexits.h
    public static final int EX_OK = 0;
    public static final int EX_GENERAL = 1;
    public static final int EX_USAGE = 64;
    public static final int EX_SOFTWARE = 70;
    public static final int EX_CONFIG = 78;

    public static void main(String... args) {
        System.setProperty("log4j2.Script.enableLanguages", "javascript");
        ThreadContext.put("side", "");
        final Logger LOGGER = LogManager.getLogger();
        try {
            (new SshMitm(args)).run();
        } catch (ParameterException pe) {
            System.exit(EX_USAGE);
        } catch (WorkflowExecutionException wee) {
            System.exit(EX_SOFTWARE);
        } catch (ConfigurationException ce) {
            System.exit(EX_CONFIG);
        } catch (Exception e) {
            LOGGER.info("Encountered an unknown exception. See debug for more info.");
            LOGGER.info(e);
            System.exit(EX_GENERAL);
        }
        System.exit(EX_OK);
    }
}
