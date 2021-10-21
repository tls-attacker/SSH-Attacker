/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.config.Config;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.state.SshContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.reflections.Reflections;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.security.Security;
import java.util.Set;

import static org.junit.Assert.fail;

public class CyclicParserSerializerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    //ToDo testParserSerializerPairs is equal to the Test with DefaultConstructors at the moment. If the classes are constructed from the config file
    // in the future the return of the getConstructor() method has to be adapted
    @Test
    public void testParserSerializerPairs() {
        Reflections reflections = new Reflections("de.rub.nds.sshattacker.core.protocol");
        Set<Class<? extends ProtocolMessageParser>> parserClasses =
                reflections.getSubTypesOf(ProtocolMessageParser.class);
        LOGGER.info("ProtocolMessageParser classes:" + parserClasses.size());
        ProtocolMessageParser<? extends ProtocolMessage> parser = null;
        ProtocolMessagePreparator<? extends ProtocolMessage> preparator = null;
        ProtocolMessage message = null;
        Config config = null;
        ProtocolMessageSerializer<? extends ProtocolMessage> serializer = null;
        for (Class<? extends ProtocolMessageParser> someParserClass : parserClasses) {
            if (Modifier.isAbstract(someParserClass.getModifiers())) {
                LOGGER.info("Skipping:" + someParserClass.getSimpleName());
                continue;
            }
            String testName = someParserClass.getSimpleName().replace("Parser", "");

            Class<? extends ProtocolMessagePreparator> preparatorClass = null;
            try {
                preparatorClass = getPreparator(testName);
                if (Modifier.isAbstract(preparatorClass.getModifiers())) {
                    LOGGER.info("Skipping:" + preparatorClass.getSimpleName());
                    continue;
                }
            } catch (ClassNotFoundException e) {
                LOGGER.warn(e);
            }

            LOGGER.info("Testing:" + testName);
            //possibility to loop over different Ssh-Versions, to test each cyclic
            // Trying to find equivalent preparator, message and serializer
            try {
                Class<? extends ProtocolMessage> protocolMessageClass = getProtocolMessage(testName);
                try {
                    Constructor tempConstructor = getMessageConstructor(protocolMessageClass);
                    if (tempConstructor != null) {
                        message = (ProtocolMessage) getMessageConstructor(protocolMessageClass)
                                .newInstance();
                    } else {
                        fail("Could not find Constructor for " + testName);
                    }
                } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                    fail("Could not create message instance for " + testName);
                }

                try {
                    SshContext context = new SshContext();
                    config = context.getConfig();
                    if (testName.equals("EcdhKeyExchangeInitMessage")) {
                        context.setKeyExchangeAlgorithm(KeyExchangeAlgorithm.ECDH_SHA2_NISTP256);
                    }
                    preparator = (ProtocolMessagePreparator) getConstructor(preparatorClass, 2)
                            .newInstance(context, message);
                } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                    fail("Could not create preparator instance for " + testName);
                }
                // Preparing message
                try {
                    preparator.prepare();
                } catch (UnsupportedOperationException E) {
                    LOGGER.info("Preparator for " + testName + " is unsupported yet");
                    continue;
                }
                Class<? extends ProtocolMessageSerializer> serializerClass = getSerializer(testName);
                try {
                    serializer = (ProtocolMessageSerializer) getConstructor(serializerClass, 1).newInstance(message);
                } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                    fail("Could not create serializer instance for " + testName);
                }
                byte[] serializedMessage = serializer.serialize();
                try {
                    parser = (ProtocolMessageParser) getConstructor(someParserClass, 2).newInstance(
                            serializedMessage, 0);
                } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                    fail("Could not create parser instance for " + testName);
                }
                try {
                    message = parser.parse();
                } catch (UnsupportedOperationException E) {
                    LOGGER.info("##########" + testName + " parsing is unsupported!");
                    continue;
                }
                try {
                    serializer = (ProtocolMessageSerializer) getConstructor(serializerClass, 1).newInstance(message);
                } catch (InstantiationException | IllegalAccessException | IllegalArgumentException
                        | InvocationTargetException ex) {
                    fail("Could not create serializer instance for " + testName);
                }
                Assert.assertArrayEquals(testName + " failed", serializedMessage, serializer.serialize());
                LOGGER.info("......." + testName + " - " + " works as expected!");
            } catch (Exception ex) {
                LOGGER.error(ex);
                fail("Could not execute " + testName + " - ");
            }
        }
    }


    @Test
    public void testParserSerializerDefaultConstructorPairs() {
        Reflections reflections = new Reflections("de.rub.nds.sshattacker.core.protocol");
        Set<Class<? extends ProtocolMessageParser>> parserClasses =
                reflections.getSubTypesOf(ProtocolMessageParser.class);
        LOGGER.info("ProtocolMessageParser classes:" + parserClasses.size());
        ProtocolMessageParser<? extends ProtocolMessage> parser = null;
        ProtocolMessagePreparator<? extends ProtocolMessage> preparator = null;
        ProtocolMessage message = null;
        ProtocolMessageSerializer<? extends ProtocolMessage> serializer = null;
        for (Class<? extends ProtocolMessageParser> someParserClass : parserClasses) {
            if (Modifier.isAbstract(someParserClass.getModifiers())) {
                LOGGER.info("Skipping:" + someParserClass.getSimpleName());
                continue;
            }
            String testName = someParserClass.getSimpleName().replace("Parser", "");
            LOGGER.info("Testing:" + testName);

            Class<? extends ProtocolMessagePreparator> preparatorClass = null;
            try {
                preparatorClass = getPreparator(testName);
                if (Modifier.isAbstract(preparatorClass.getModifiers())) {
                    LOGGER.info("Skipping:" + preparatorClass.getSimpleName());
                    continue;
                }
            } catch (ClassNotFoundException e) {
                LOGGER.warn(e);
            }

            SshContext context = new SshContext();
            if (testName.equals("EcdhKeyExchangeInitMessage")) {
                context.setKeyExchangeAlgorithm(KeyExchangeAlgorithm.ECDH_SHA2_NISTP256);
            }

            // Trying to find equivalent preparator, message and serializer
            try {
                Class<? extends ProtocolMessage> protocolMessageClass = getProtocolMessage(testName);
                try {
                    Constructor tempConstructor = getDefaultMessageConstructor(protocolMessageClass);
                    if (tempConstructor != null) {
                        message =
                                (ProtocolMessage) getDefaultMessageConstructor(protocolMessageClass).newInstance();
                    } else {
                        fail("Could not find Constructor for " + testName);
                    }
                } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                    fail("Could not create message instance for " + testName);
                }

                try {
                    preparator = (ProtocolMessagePreparator) getConstructor(preparatorClass, 2)
                            .newInstance(context, message);
                } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                    ex.printStackTrace();
                    fail("Could not create preparator instance for " + testName);
                }
                // Preparing message
                try {
                    preparator.prepare();
                } catch (UnsupportedOperationException E) {
                    LOGGER.info("Preparator for " + testName + " is unsupported yet");
                    continue;
                }
                Class<? extends ProtocolMessageSerializer> serializerClass = getSerializer(testName);
                try {
                    serializer = (ProtocolMessageSerializer) getConstructor(serializerClass, 1).newInstance(message);
                } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                    fail("Could not create serializer instance for " + testName);
                }
                byte[] serializedMessage = serializer.serialize();
                try {
                    parser = (ProtocolMessageParser) getConstructor(someParserClass, 2).newInstance(serializedMessage, 0);
                } catch (SecurityException | InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException ex) {
                    fail("Could not create parser instance for " + testName);
                }
                try {
                    message = parser.parse();
                } catch (UnsupportedOperationException E) {
                    LOGGER.info("##########" + testName + " parsing is unsupported!");
                    continue;
                }
                try {
                    serializer = (ProtocolMessageSerializer) getConstructor(serializerClass, 1).newInstance(message);
                } catch (InstantiationException | IllegalAccessException | IllegalArgumentException
                        | InvocationTargetException ex) {
                    fail("Could not create serializer instance for " + testName);
                }
                Assert.assertArrayEquals(testName + " failed", serializedMessage, serializer.serialize());
                LOGGER.info("......." + testName + " works as expected!");
            } catch (ClassNotFoundException ex) {
                fail("Could not execute " + testName);
            }
        }
    }

    private Class<? extends ProtocolMessage> getProtocolMessage(String testName) throws ClassNotFoundException {
        String[] messageNames = {"de.rub.nds.sshattacker.core.protocol.authentication.message." + testName, "de.rub.nds.sshattacker.core.protocol.connection.message." + testName, "de.rub.nds.sshattacker.core.protocol.transport.message." + testName};
        for (String messageName : messageNames) {
            try {
                return (Class<? extends ProtocolMessage>) Class.forName(messageName);
            } catch (ClassNotFoundException E) {
                try {
                    return (Class<? extends ProtocolMessage>) Class.forName(messageName + "Message");
                } catch (ClassNotFoundException ex) {
                }
            }
        }
        throw new ClassNotFoundException("Could not find Message for " + testName);
    }

    private Class<? extends ProtocolMessagePreparator> getPreparator(String testName) throws ClassNotFoundException {
        String[] preparatorNames = {"de.rub.nds.sshattacker.core.protocol.authentication.preparator." + testName, "de.rub.nds.sshattacker.core.protocol.connection.preparator." + testName, "de.rub.nds.sshattacker.core.protocol.transport.preparator." + testName};
        for (String preparatorName : preparatorNames) {
            try {
                return (Class<? extends ProtocolMessagePreparator>) Class.forName(preparatorName + "Preparator");
            } catch (ClassNotFoundException E) {
                try {
                    return (Class<? extends ProtocolMessagePreparator>) Class.forName(preparatorName + "MessagePreparator");
                } catch (ClassNotFoundException ex) {
                }
            }
        }
        throw new ClassNotFoundException("Could not find Preparator for " + testName);
    }

    private Class<? extends ProtocolMessageSerializer> getSerializer(String testName) throws ClassNotFoundException {
        String[] serializerNames = {"de.rub.nds.sshattacker.core.protocol.authentication.serializer." + testName, "de.rub.nds.sshattacker.core.protocol.connection.serializer." + testName, "de.rub.nds.sshattacker.core.protocol.transport.serializer." + testName};
        for (String serializerName : serializerNames) {
            try {
                return (Class<? extends ProtocolMessageSerializer>) Class.forName(serializerName + "Serializer");
            } catch (ClassNotFoundException E) {
                try {
                    return (Class<? extends ProtocolMessageSerializer>) Class.forName(serializerName + "MessageSerializer");
                } catch (ClassNotFoundException ex) {
                }
            }
        }
        throw new ClassNotFoundException("Could not find Serializer for " + testName);
    }

    private Constructor getMessageConstructor(Class someClass) {
        for (Constructor c : someClass.getConstructors()) {
            if (c.getParameterCount() == 0) {

                return c;

            }
        }
        LOGGER.warn("Could not find Constructor: " + someClass.getSimpleName());
        return null;
    }

    private Constructor getDefaultMessageConstructor(Class someClass) {
        for (Constructor c : someClass.getDeclaredConstructors()) {
            if (c.getParameterCount() == 0) {
                return c;
            }
        }
        LOGGER.warn("Could not find Constructor: " + someClass.getSimpleName());
        return null;
    }

    private Constructor getConstructor(Class someClass, int numberOfArguments) {
        for (Constructor c : someClass.getConstructors()) {
            if (c.getParameterCount() == numberOfArguments) {
                return c;
            }
        }
        LOGGER.warn("Could not find Constructor: " + someClass.getSimpleName());
        return null;
    }
}
