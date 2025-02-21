/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.KeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.KeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageHandler extends SshMessageHandler<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, KeyExchangeInitMessage object) {
        if (context.isHandleAsClient()) {
            context.setServerCookie(object.getCookie().getValue());
            context.setServerSupportedKeyExchangeAlgorithms(
                    Converter.nameListToEnumValues(
                            object.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            context.setServerSupportedHostKeyAlgorithms(
                    Converter.nameListToEnumValues(
                            object.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAlgorithm.class));
            context.setServerSupportedEncryptionAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            object.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            context.setServerSupportedEncryptionAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            object.getEncryptionAlgorithmsServerToClient().getValue(),
                            EncryptionAlgorithm.class));
            context.setServerSupportedMacAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            object.getMacAlgorithmsClientToServer().getValue(),
                            MacAlgorithm.class));
            context.setServerSupportedMacAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            object.getMacAlgorithmsServerToClient().getValue(),
                            MacAlgorithm.class));
            context.setServerSupportedCompressionMethodsClientToServer(
                    Converter.nameListToEnumValues(
                            object.getCompressionMethodsClientToServer().getValue(),
                            CompressionMethod.class));
            context.setServerSupportedCompressionMethodsServerToClient(
                    Converter.nameListToEnumValues(
                            object.getCompressionMethodsServerToClient().getValue(),
                            CompressionMethod.class));
            context.setServerSupportedLanguagesClientToServer(
                    Converter.nameListStringToStringList(
                            object.getLanguagesClientToServer().getValue()));
            context.setServerSupportedLanguagesServerToClient(
                    Converter.nameListStringToStringList(
                            object.getLanguagesServerToClient().getValue()));
            context.setServerReserved(object.getReserved().getValue());

            context.getExchangeHashInputHolder().setServerKeyExchangeInit(object);

            context.setServerSupportsExtensionNegotiation(
                    checkServerSupportForExtensionNegotiation(context));
            context.setStrictKeyExchangeEnabled(
                    containsKeyExchangeAlgorithm(
                                    KeyExchangeAlgorithm.KEX_STRICT_S_V00_OPENSSH_COM,
                                    context.getServerSupportedKeyExchangeAlgorithms()
                                            .orElse(List.of()))
                            && containsKeyExchangeAlgorithm(
                                    KeyExchangeAlgorithm.KEX_STRICT_C_V00_OPENSSH_COM,
                                    context.getConfig().getClientSupportedKeyExchangeAlgorithms()));
        } else {
            context.setClientCookie(object.getCookie().getValue());
            context.setClientSupportedKeyExchangeAlgorithms(
                    Converter.nameListToEnumValues(
                            object.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            context.setClientSupportedHostKeyAlgorithms(
                    Converter.nameListToEnumValues(
                            object.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAlgorithm.class));
            context.setClientSupportedEncryptionAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            object.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            context.setClientSupportedEncryptionAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            object.getEncryptionAlgorithmsServerToClient().getValue(),
                            EncryptionAlgorithm.class));
            context.setClientSupportedMacAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            object.getMacAlgorithmsClientToServer().getValue(),
                            MacAlgorithm.class));
            context.setClientSupportedMacAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            object.getMacAlgorithmsServerToClient().getValue(),
                            MacAlgorithm.class));
            context.setClientSupportedCompressionMethodsClientToServer(
                    Converter.nameListToEnumValues(
                            object.getCompressionMethodsClientToServer().getValue(),
                            CompressionMethod.class));
            context.setClientSupportedCompressionMethodsServerToClient(
                    Converter.nameListToEnumValues(
                            object.getCompressionMethodsServerToClient().getValue(),
                            CompressionMethod.class));
            context.setClientSupportedLanguagesClientToServer(
                    Converter.nameListStringToStringList(
                            object.getLanguagesClientToServer().getValue()));
            context.setClientSupportedLanguagesServerToClient(
                    Converter.nameListStringToStringList(
                            object.getLanguagesServerToClient().getValue()));
            context.setClientReserved(object.getReserved().getValue());

            context.getExchangeHashInputHolder().setClientKeyExchangeInit(object);

            context.setClientSupportsExtensionNegotiation(
                    checkClientSupportForExtensionNegotiation(context));
            context.setStrictKeyExchangeEnabled(
                    containsKeyExchangeAlgorithm(
                                    KeyExchangeAlgorithm.KEX_STRICT_C_V00_OPENSSH_COM,
                                    context.getClientSupportedKeyExchangeAlgorithms()
                                            .orElse(List.of()))
                            && containsKeyExchangeAlgorithm(
                                    KeyExchangeAlgorithm.KEX_STRICT_S_V00_OPENSSH_COM,
                                    context.getConfig().getServerSupportedKeyExchangeAlgorithms()));
        }
        pickAlgorithms(context);
    }

    private static boolean checkClientSupportForExtensionNegotiation(SshContext context) {
        return containsKeyExchangeAlgorithm(
                KeyExchangeAlgorithm.EXT_INFO_C,
                context.getClientSupportedKeyExchangeAlgorithms().orElse(List.of()));
    }

    private static boolean checkServerSupportForExtensionNegotiation(SshContext context) {
        return containsKeyExchangeAlgorithm(
                KeyExchangeAlgorithm.EXT_INFO_S,
                context.getServerSupportedKeyExchangeAlgorithms().orElse(List.of()));
    }

    private static boolean containsKeyExchangeAlgorithm(
            KeyExchangeAlgorithm keyExchangeAlgorithm, List<KeyExchangeAlgorithm> algorithms) {
        for (KeyExchangeAlgorithm algorithm : algorithms) {
            if (algorithm == keyExchangeAlgorithm) {
                return true;
            }
        }
        return false;
    }

    private static void pickAlgorithms(SshContext context) {
        // if enforceSettings is true, the algorithms are expected to be
        // already set in the context
        if (!context.getConfig().getEnforceSettings()) {
            context.setKeyExchangeAlgorithm(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser().getClientSupportedKeyExchangeAlgorithms(),
                                    context.getChooser().getServerSupportedKeyExchangeAlgorithms())
                            .orElse(null));

            context.setEncryptionAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedEncryptionAlgorithmsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedEncryptionAlgorithmsClientToServer())
                            .orElse(null));

            context.setEncryptionAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedEncryptionAlgorithmsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedEncryptionAlgorithmsServerToClient())
                            .orElse(null));

            context.setHostKeyAlgorithm(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser().getClientSupportedHostKeyAlgorithms(),
                                    context.getChooser().getServerSupportedHostKeyAlgorithms())
                            .orElse(null));

            context.setMacAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedMacAlgorithmsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedMacAlgorithmsClientToServer())
                            .orElse(null));

            context.setMacAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedMacAlgorithmsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedMacAlgorithmsServerToClient())
                            .orElse(null));

            context.setCompressionMethodClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCompressionMethodsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedCompressionMethodsClientToServer())
                            .orElse(null));

            context.setCompressionMethodServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCompressionMethodsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedCompressionMethodsServerToClient())
                            .orElse(null));
            LOGGER.info(
                    """
                    Selected algorithms for key exchange and secure channel:

                        Key exchange algorithm: {}
                        Host key algorithm: {}
                        Encryption algorithm (client to server): {}
                        Encryption algorithm (server to client): {}
                        MAC algorithm (client to server): {}
                        MAC algorithm (server to client): {}
                        Compression algorithm (client to server): {}
                        Compression algorithm (server to client): {}
                    """,
                    context.getKeyExchangeAlgorithm().orElse(null),
                    context.getHostKeyAlgorithm().orElse(null),
                    context.getEncryptionAlgorithmClientToServer().orElse(null),
                    context.getEncryptionAlgorithmServerToClient().orElse(null),
                    context.getEncryptionAlgorithmClientToServer()
                                            .orElse(EncryptionAlgorithm.NONE)
                                            .getType()
                                    != EncryptionAlgorithmType.AEAD
                            ? context.getMacAlgorithmClientToServer().orElse(null)
                            : "<implicit>",
                    context.getEncryptionAlgorithmServerToClient()
                                            .orElse(EncryptionAlgorithm.NONE)
                                            .getType()
                                    != EncryptionAlgorithmType.AEAD
                            ? context.getEncryptionAlgorithmServerToClient().orElse(null)
                            : "<implicit>",
                    context.getCompressionMethodClientToServer().orElse(null),
                    context.getCompressionMethodServerToClient().orElse(null));
        }
    }

    @Override
    public KeyExchangeInitMessageParser getParser(byte[] array, SshContext context) {
        return new KeyExchangeInitMessageParser(array);
    }

    @Override
    public KeyExchangeInitMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new KeyExchangeInitMessageParser(array, startPosition);
    }

    public static final KeyExchangeInitMessagePreparator PREPARATOR =
            new KeyExchangeInitMessagePreparator();

    public static final KeyExchangeInitMessageSerializer SERIALIZER =
            new KeyExchangeInitMessageSerializer();
}
