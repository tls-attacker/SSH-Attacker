/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.KeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

public class KeyExchangeInitMessage extends SshMessage<KeyExchangeInitMessage> {

    private ModifiableByteArray cookie;
    private ModifiableInteger keyExchangeAlgorithmsLength;
    private ModifiableString keyExchangeAlgorithms;
    private ModifiableInteger serverHostKeyAlgorithmsLength;
    private ModifiableString serverHostKeyAlgorithms;
    private ModifiableInteger encryptionAlgorithmsClientToServerLength;
    private ModifiableString encryptionAlgorithmsClientToServer;
    private ModifiableInteger encryptionAlgorithmsServerToClientLength;
    private ModifiableString encryptionAlgorithmsServerToClient;
    private ModifiableInteger macAlgorithmsClientToServerLength;
    private ModifiableString macAlgorithmsClientToServer;
    private ModifiableInteger macAlgorithmsServerToClientLength;
    private ModifiableString macAlgorithmsServerToClient;
    private ModifiableInteger compressionMethodsClientToServerLength;
    private ModifiableString compressionMethodsClientToServer;
    private ModifiableInteger compressionMethodsServerToClientLength;
    private ModifiableString compressionMethodsServerToClient;
    private ModifiableInteger languagesClientToServerLength;
    private ModifiableString languagesClientToServer;
    private ModifiableInteger languagesServerToClientLength;
    private ModifiableString languagesServerToClient;
    private ModifiableByte firstKeyExchangePacketFollows;
    private ModifiableInteger reserved;

    public ModifiableByteArray getCookie() {
        return cookie;
    }

    public void setCookie(ModifiableByteArray cookie) {
        this.cookie = cookie;
    }

    public void setCookie(byte[] cookie) {
        this.cookie = ModifiableVariableFactory.safelySetValue(this.cookie, cookie);
    }

    public ModifiableInteger getKeyExchangeAlgorithmsLength() {
        return keyExchangeAlgorithmsLength;
    }

    public void setKeyExchangeAlgorithmsLength(ModifiableInteger keyExchangeAlgorithmsLength) {
        this.keyExchangeAlgorithmsLength = keyExchangeAlgorithmsLength;
    }

    public void setKeyExchangeAlgorithmsLength(int keyExchangeAlgorithmsLength) {
        this.keyExchangeAlgorithmsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.keyExchangeAlgorithmsLength, keyExchangeAlgorithmsLength);
    }

    public ModifiableString getKeyExchangeAlgorithms() {
        return keyExchangeAlgorithms;
    }

    public void setKeyExchangeAlgorithms(ModifiableString keyExchangeAlgorithms) {
        setKeyExchangeAlgorithms(keyExchangeAlgorithms, false);
    }

    public void setKeyExchangeAlgorithms(String keyExchangeAlgorithms) {
        setKeyExchangeAlgorithms(keyExchangeAlgorithms, false);
    }

    public void setKeyExchangeAlgorithms(String[] keyExchangeAlgorithms) {
        setKeyExchangeAlgorithms(keyExchangeAlgorithms, false);
    }

    public void setKeyExchangeAlgorithms(List<KeyExchangeAlgorithm> keyExchangeAlgorithms) {
        setKeyExchangeAlgorithms(keyExchangeAlgorithms, false);
    }

    public void setKeyExchangeAlgorithms(
            ModifiableString keyExchangeAlgorithms, boolean adjustLengthField) {
        this.keyExchangeAlgorithms = keyExchangeAlgorithms;
        if (adjustLengthField) {
            setKeyExchangeAlgorithmsLength(
                    this.keyExchangeAlgorithms
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setKeyExchangeAlgorithms(String keyExchangeAlgorithms, boolean adjustLengthField) {
        this.keyExchangeAlgorithms =
                ModifiableVariableFactory.safelySetValue(
                        this.keyExchangeAlgorithms, keyExchangeAlgorithms);
        if (adjustLengthField) {
            setKeyExchangeAlgorithmsLength(
                    this.keyExchangeAlgorithms
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyKeyExchangeAlgorithms(
            String keyExchangeAlgorithms, boolean adjustLengthField, Config config) {
        if (this.keyExchangeAlgorithms == null
                || this.keyExchangeAlgorithms.getOriginalValue() == null) {
            this.keyExchangeAlgorithms =
                    ModifiableVariableFactory.safelySetValue(
                            this.keyExchangeAlgorithms, keyExchangeAlgorithms);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || keyExchangeAlgorithmsLength == null
                    || keyExchangeAlgorithmsLength.getOriginalValue() == null) {
                setKeyExchangeAlgorithmsLength(
                        this.keyExchangeAlgorithms
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setKeyExchangeAlgorithms(
            String[] keyExchangeAlgorithms, boolean adjustLengthField) {
        String nameList =
                String.join("" + CharConstants.ALGORITHM_SEPARATOR, keyExchangeAlgorithms);
        setKeyExchangeAlgorithms(nameList, adjustLengthField);
    }

    public void setKeyExchangeAlgorithms(
            List<KeyExchangeAlgorithm> keyExchangeAlgorithms, boolean adjustLengthField) {
        String nameList =
                keyExchangeAlgorithms.stream()
                        .map(KeyExchangeAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setKeyExchangeAlgorithms(nameList, adjustLengthField);
    }

    public ModifiableInteger getServerHostKeyAlgorithmsLength() {
        return serverHostKeyAlgorithmsLength;
    }

    public void setServerHostKeyAlgorithmsLength(ModifiableInteger serverHostKeyAlgorithmsLength) {
        this.serverHostKeyAlgorithmsLength = serverHostKeyAlgorithmsLength;
    }

    public void setServerHostKeyAlgorithmsLength(int serverHostKeyAlgorithmsLength) {
        this.serverHostKeyAlgorithmsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.serverHostKeyAlgorithmsLength, serverHostKeyAlgorithmsLength);
    }

    public ModifiableString getServerHostKeyAlgorithms() {
        return serverHostKeyAlgorithms;
    }

    public void setServerHostKeyAlgorithms(ModifiableString serverHostKeyAlgorithms) {
        setServerHostKeyAlgorithms(serverHostKeyAlgorithms, false);
    }

    public void setServerHostKeyAlgorithms(String serverHostKeyAlgorithms) {
        setServerHostKeyAlgorithms(serverHostKeyAlgorithms, false);
    }

    public void setServerHostKeyAlgorithms(String[] serverHostKeyAlgorithms) {
        setServerHostKeyAlgorithms(serverHostKeyAlgorithms, false);
    }

    public void setServerHostKeyAlgorithms(List<PublicKeyAlgorithm> serverHostKeyAlgorithms) {
        setServerHostKeyAlgorithms(serverHostKeyAlgorithms, false);
    }

    public void setServerHostKeyAlgorithms(
            ModifiableString serverHostKeyAlgorithms, boolean adjustLengthField) {
        this.serverHostKeyAlgorithms = serverHostKeyAlgorithms;
        if (adjustLengthField) {
            setServerHostKeyAlgorithmsLength(
                    this.serverHostKeyAlgorithms
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setServerHostKeyAlgorithms(
            String serverHostKeyAlgorithms, boolean adjustLengthField) {
        this.serverHostKeyAlgorithms =
                ModifiableVariableFactory.safelySetValue(
                        this.serverHostKeyAlgorithms, serverHostKeyAlgorithms);
        if (adjustLengthField) {
            setServerHostKeyAlgorithmsLength(
                    this.serverHostKeyAlgorithms
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyServerHostKeyAlgorithms(
            String serverHostKeyAlgorithms, boolean adjustLengthField, Config config) {
        if (this.serverHostKeyAlgorithms == null
                || this.serverHostKeyAlgorithms.getOriginalValue() == null) {
            this.serverHostKeyAlgorithms =
                    ModifiableVariableFactory.safelySetValue(
                            this.serverHostKeyAlgorithms, serverHostKeyAlgorithms);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || serverHostKeyAlgorithmsLength == null
                    || serverHostKeyAlgorithmsLength.getOriginalValue() == null) {
                setServerHostKeyAlgorithmsLength(
                        this.serverHostKeyAlgorithms
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setServerHostKeyAlgorithms(
            String[] serverHostKeyAlgorithms, boolean adjustLengthField) {
        String nameList =
                String.join("" + CharConstants.ALGORITHM_SEPARATOR, serverHostKeyAlgorithms);
        setServerHostKeyAlgorithms(nameList, adjustLengthField);
    }

    public void setServerHostKeyAlgorithms(
            List<PublicKeyAlgorithm> serverHostKeyAlgorithms, boolean adjustLengthField) {
        String nameList =
                serverHostKeyAlgorithms.stream()
                        .map(PublicKeyAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setServerHostKeyAlgorithms(nameList, adjustLengthField);
    }

    public ModifiableInteger getEncryptionAlgorithmsClientToServerLength() {
        return encryptionAlgorithmsClientToServerLength;
    }

    public void setEncryptionAlgorithmsClientToServerLength(
            ModifiableInteger encryptionAlgorithmsClientToServerLength) {
        this.encryptionAlgorithmsClientToServerLength = encryptionAlgorithmsClientToServerLength;
    }

    public void setEncryptionAlgorithmsClientToServerLength(
            int encryptionAlgorithmsClientToServerLength) {
        this.encryptionAlgorithmsClientToServerLength =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptionAlgorithmsClientToServerLength,
                        encryptionAlgorithmsClientToServerLength);
    }

    public ModifiableString getEncryptionAlgorithmsClientToServer() {
        return encryptionAlgorithmsClientToServer;
    }

    public void setEncryptionAlgorithmsClientToServer(
            ModifiableString encryptionAlgorithmsClientToServer) {
        setEncryptionAlgorithmsClientToServer(encryptionAlgorithmsClientToServer, false);
    }

    public void setEncryptionAlgorithmsClientToServer(String encryptionAlgorithmsClientToServer) {
        setEncryptionAlgorithmsClientToServer(encryptionAlgorithmsClientToServer, false);
    }

    public void setEncryptionAlgorithmsClientToServer(String[] encryptionAlgorithmsClientToServer) {
        setEncryptionAlgorithmsClientToServer(encryptionAlgorithmsClientToServer, false);
    }

    public void setEncryptionAlgorithmsClientToServer(
            List<EncryptionAlgorithm> encryptionAlgorithmsClientToServer) {
        setEncryptionAlgorithmsClientToServer(encryptionAlgorithmsClientToServer, false);
    }

    public void setEncryptionAlgorithmsClientToServer(
            ModifiableString encryptionAlgorithmsClientToServer, boolean adjustLengthField) {
        this.encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer;
        if (adjustLengthField) {
            setEncryptionAlgorithmsClientToServerLength(
                    this.encryptionAlgorithmsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setEncryptionAlgorithmsClientToServer(
            String encryptionAlgorithmsClientToServer, boolean adjustLengthField) {
        this.encryptionAlgorithmsClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptionAlgorithmsClientToServer,
                        encryptionAlgorithmsClientToServer);
        if (adjustLengthField) {
            setEncryptionAlgorithmsClientToServerLength(
                    this.encryptionAlgorithmsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyEncryptionAlgorithmsClientToServer(
            String encryptionAlgorithmsClientToServer, boolean adjustLengthField, Config config) {
        if (this.encryptionAlgorithmsClientToServer == null
                || this.encryptionAlgorithmsClientToServer.getOriginalValue() == null) {
            this.encryptionAlgorithmsClientToServer =
                    ModifiableVariableFactory.safelySetValue(
                            this.encryptionAlgorithmsClientToServer,
                            encryptionAlgorithmsClientToServer);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || encryptionAlgorithmsClientToServerLength == null
                    || encryptionAlgorithmsClientToServerLength.getOriginalValue() == null) {
                setEncryptionAlgorithmsClientToServerLength(
                        this.encryptionAlgorithmsClientToServer
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setEncryptionAlgorithmsClientToServer(
            String[] encryptionAlgorithmsClientToServer, boolean adjustLengthField) {
        String nameList =
                String.join(
                        "" + CharConstants.ALGORITHM_SEPARATOR, encryptionAlgorithmsClientToServer);
        setEncryptionAlgorithmsClientToServer(nameList, adjustLengthField);
    }

    public void setEncryptionAlgorithmsClientToServer(
            List<EncryptionAlgorithm> encryptionAlgorithmsClientToServer,
            boolean adjustLengthField) {
        String nameList =
                encryptionAlgorithmsClientToServer.stream()
                        .map(EncryptionAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setEncryptionAlgorithmsClientToServer(nameList, adjustLengthField);
    }

    public ModifiableInteger getEncryptionAlgorithmsServerToClientLength() {
        return encryptionAlgorithmsServerToClientLength;
    }

    public void setEncryptionAlgorithmsServerToClientLength(
            ModifiableInteger encryptionAlgorithmsServerToClientLength) {
        this.encryptionAlgorithmsServerToClientLength = encryptionAlgorithmsServerToClientLength;
    }

    public void setEncryptionAlgorithmsServerToClientLength(
            int encryptionAlgorithmsServerToClientLength) {
        this.encryptionAlgorithmsServerToClientLength =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptionAlgorithmsServerToClientLength,
                        encryptionAlgorithmsServerToClientLength);
    }

    public ModifiableString getEncryptionAlgorithmsServerToClient() {
        return encryptionAlgorithmsServerToClient;
    }

    public void setEncryptionAlgorithmsServerToClient(
            ModifiableString encryptionAlgorithmsServerToClient) {
        setEncryptionAlgorithmsServerToClient(encryptionAlgorithmsServerToClient, false);
    }

    public void setEncryptionAlgorithmsServerToClient(String encryptionAlgorithmsServerToClient) {
        setEncryptionAlgorithmsServerToClient(encryptionAlgorithmsServerToClient, false);
    }

    public void setEncryptionAlgorithmsServerToClient(String[] encryptionAlgorithmsServerToClient) {
        setEncryptionAlgorithmsServerToClient(encryptionAlgorithmsServerToClient, false);
    }

    public void setEncryptionAlgorithmsServerToClient(
            List<EncryptionAlgorithm> encryptionAlgorithmsServerToClient) {
        setEncryptionAlgorithmsServerToClient(encryptionAlgorithmsServerToClient, false);
    }

    public void setEncryptionAlgorithmsServerToClient(
            ModifiableString encryptionAlgorithmsServerToClient, boolean adjustLengthField) {
        this.encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient;
        if (adjustLengthField) {
            setEncryptionAlgorithmsServerToClientLength(
                    this.encryptionAlgorithmsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setEncryptionAlgorithmsServerToClient(
            String encryptionAlgorithmsServerToClient, boolean adjustLengthField) {
        this.encryptionAlgorithmsServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptionAlgorithmsServerToClient,
                        encryptionAlgorithmsServerToClient);
        if (adjustLengthField) {
            setEncryptionAlgorithmsServerToClientLength(
                    this.encryptionAlgorithmsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyEncryptionAlgorithmsServerToClient(
            String encryptionAlgorithmsServerToClient, boolean adjustLengthField, Config config) {
        if (this.encryptionAlgorithmsServerToClient == null
                || this.encryptionAlgorithmsServerToClient.getOriginalValue() == null) {
            this.encryptionAlgorithmsServerToClient =
                    ModifiableVariableFactory.safelySetValue(
                            this.encryptionAlgorithmsServerToClient,
                            encryptionAlgorithmsServerToClient);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || encryptionAlgorithmsServerToClientLength == null
                    || encryptionAlgorithmsServerToClientLength.getOriginalValue() == null) {
                setEncryptionAlgorithmsServerToClientLength(
                        this.encryptionAlgorithmsServerToClient
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setEncryptionAlgorithmsServerToClient(
            String[] encryptionAlgorithmsServerToClient, boolean adjustLengthField) {
        String nameList =
                String.join(
                        "" + CharConstants.ALGORITHM_SEPARATOR, encryptionAlgorithmsServerToClient);
        setEncryptionAlgorithmsServerToClient(nameList, adjustLengthField);
    }

    public void setEncryptionAlgorithmsServerToClient(
            List<EncryptionAlgorithm> encryptionAlgorithmsServerToClient,
            boolean adjustLengthField) {
        String nameList =
                encryptionAlgorithmsServerToClient.stream()
                        .map(EncryptionAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setEncryptionAlgorithmsServerToClient(nameList, adjustLengthField);
    }

    public ModifiableInteger getMacAlgorithmsClientToServerLength() {
        return macAlgorithmsClientToServerLength;
    }

    public void setMacAlgorithmsClientToServerLength(
            ModifiableInteger macAlgorithmsClientToServerLength) {
        this.macAlgorithmsClientToServerLength = macAlgorithmsClientToServerLength;
    }

    public void setMacAlgorithmsClientToServerLength(int macAlgorithmsClientToServerLength) {
        this.macAlgorithmsClientToServerLength =
                ModifiableVariableFactory.safelySetValue(
                        this.macAlgorithmsClientToServerLength, macAlgorithmsClientToServerLength);
    }

    public ModifiableString getMacAlgorithmsClientToServer() {
        return macAlgorithmsClientToServer;
    }

    public void setMacAlgorithmsClientToServer(ModifiableString macAlgorithmsClientToServer) {
        setMacAlgorithmsClientToServer(macAlgorithmsClientToServer, false);
    }

    public void setMacAlgorithmsClientToServer(String macAlgorithmsClientToServer) {
        setMacAlgorithmsClientToServer(macAlgorithmsClientToServer, false);
    }

    public void setMacAlgorithmsClientToServer(String[] macAlgorithmsClientToServer) {
        setMacAlgorithmsClientToServer(macAlgorithmsClientToServer, false);
    }

    public void setMacAlgorithmsClientToServer(List<MacAlgorithm> macAlgorithmsClientToServer) {
        setMacAlgorithmsClientToServer(macAlgorithmsClientToServer, false);
    }

    public void setMacAlgorithmsClientToServer(
            ModifiableString macAlgorithmsClientToServer, boolean adjustLengthField) {
        this.macAlgorithmsClientToServer = macAlgorithmsClientToServer;
        if (adjustLengthField) {
            setMacAlgorithmsClientToServerLength(
                    this.macAlgorithmsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setMacAlgorithmsClientToServer(
            String macAlgorithmsClientToServer, boolean adjustLengthField) {
        this.macAlgorithmsClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.macAlgorithmsClientToServer, macAlgorithmsClientToServer);
        if (adjustLengthField) {
            setMacAlgorithmsClientToServerLength(
                    this.macAlgorithmsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyMacAlgorithmsClientToServer(
            String macAlgorithmsClientToServer, boolean adjustLengthField, Config config) {
        if (this.macAlgorithmsClientToServer == null
                || this.macAlgorithmsClientToServer.getOriginalValue() == null) {
            this.macAlgorithmsClientToServer =
                    ModifiableVariableFactory.safelySetValue(
                            this.macAlgorithmsClientToServer, macAlgorithmsClientToServer);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || macAlgorithmsClientToServerLength == null
                    || macAlgorithmsClientToServerLength.getOriginalValue() == null) {
                setMacAlgorithmsClientToServerLength(
                        this.macAlgorithmsClientToServer
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setMacAlgorithmsClientToServer(
            String[] macAlgorithmsClientToServer, boolean adjustLengthField) {
        String nameList =
                String.join("" + CharConstants.ALGORITHM_SEPARATOR, macAlgorithmsClientToServer);
        setMacAlgorithmsClientToServer(nameList, adjustLengthField);
    }

    public void setMacAlgorithmsClientToServer(
            List<MacAlgorithm> macAlgorithmsClientToServer, boolean adjustLengthField) {
        String nameList =
                macAlgorithmsClientToServer.stream()
                        .map(MacAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setMacAlgorithmsClientToServer(nameList, adjustLengthField);
    }

    public ModifiableInteger getMacAlgorithmsServerToClientLength() {
        return macAlgorithmsServerToClientLength;
    }

    public void setMacAlgorithmsServerToClientLength(
            ModifiableInteger macAlgorithmsServerToClientLength) {
        this.macAlgorithmsServerToClientLength = macAlgorithmsServerToClientLength;
    }

    public void setMacAlgorithmsServerToClientLength(int macAlgorithmsServerToClientLength) {
        this.macAlgorithmsServerToClientLength =
                ModifiableVariableFactory.safelySetValue(
                        this.macAlgorithmsServerToClientLength, macAlgorithmsServerToClientLength);
    }

    public ModifiableString getMacAlgorithmsServerToClient() {
        return macAlgorithmsServerToClient;
    }

    public void setMacAlgorithmsServerToClient(ModifiableString macAlgorithmsServerToClient) {
        setMacAlgorithmsServerToClient(macAlgorithmsServerToClient, false);
    }

    public void setMacAlgorithmsServerToClient(String macAlgorithmsServerToClient) {
        setMacAlgorithmsServerToClient(macAlgorithmsServerToClient, false);
    }

    public void setMacAlgorithmsServerToClient(String[] macAlgorithmsServerToClient) {
        setMacAlgorithmsServerToClient(macAlgorithmsServerToClient, false);
    }

    public void setMacAlgorithmsServerToClient(List<MacAlgorithm> macAlgorithmsServerToClient) {
        setMacAlgorithmsServerToClient(macAlgorithmsServerToClient, false);
    }

    public void setMacAlgorithmsServerToClient(
            ModifiableString macAlgorithmsServerToClient, boolean adjustLengthField) {
        this.macAlgorithmsServerToClient = macAlgorithmsServerToClient;
        if (adjustLengthField) {
            setMacAlgorithmsServerToClientLength(
                    this.macAlgorithmsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setMacAlgorithmsServerToClient(
            String macAlgorithmsServerToClient, boolean adjustLengthField) {
        this.macAlgorithmsServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.macAlgorithmsServerToClient, macAlgorithmsServerToClient);
        if (adjustLengthField) {
            setMacAlgorithmsServerToClientLength(
                    this.macAlgorithmsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyMacAlgorithmsServerToClient(
            String macAlgorithmsServerToClient, boolean adjustLengthField, Config config) {
        if (this.macAlgorithmsServerToClient == null
                || this.macAlgorithmsServerToClient.getOriginalValue() == null) {
            this.macAlgorithmsServerToClient =
                    ModifiableVariableFactory.safelySetValue(
                            this.macAlgorithmsServerToClient, macAlgorithmsServerToClient);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || macAlgorithmsServerToClientLength == null
                    || macAlgorithmsServerToClientLength.getOriginalValue() == null) {
                setMacAlgorithmsServerToClientLength(
                        this.macAlgorithmsServerToClient
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setMacAlgorithmsServerToClient(
            String[] macAlgorithmsServerToClient, boolean adjustLengthField) {
        String nameList =
                String.join("" + CharConstants.ALGORITHM_SEPARATOR, macAlgorithmsServerToClient);
        setMacAlgorithmsServerToClient(nameList, adjustLengthField);
    }

    public void setMacAlgorithmsServerToClient(
            List<MacAlgorithm> macAlgorithmsServerToClient, boolean adjustLengthField) {
        String nameList =
                macAlgorithmsServerToClient.stream()
                        .map(MacAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setMacAlgorithmsServerToClient(nameList, adjustLengthField);
    }

    public ModifiableInteger getCompressionMethodsClientToServerLength() {
        return compressionMethodsClientToServerLength;
    }

    public void setCompressionMethodsClientToServerLength(
            ModifiableInteger compressionMethodsClientToServerLength) {
        this.compressionMethodsClientToServerLength = compressionMethodsClientToServerLength;
    }

    public void setCompressionMethodsClientToServerLength(
            int compressionMethodsClientToServerLength) {
        this.compressionMethodsClientToServerLength =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsClientToServerLength,
                        compressionMethodsClientToServerLength);
    }

    public ModifiableString getCompressionMethodsClientToServer() {
        return compressionMethodsClientToServer;
    }

    public void setCompressionMethodsClientToServer(
            ModifiableString compressionMethodsClientToServer) {
        setCompressionMethodsClientToServer(compressionMethodsClientToServer, false);
    }

    public void setCompressionMethodsClientToServer(String compressionMethodsClientToServer) {
        setCompressionMethodsClientToServer(compressionMethodsClientToServer, false);
    }

    public void setCompressionMethodsClientToServer(String[] compressionMethodsClientToServer) {
        setCompressionMethodsClientToServer(compressionMethodsClientToServer, false);
    }

    public void setCompressionMethodsClientToServer(
            List<CompressionMethod> compressionMethodsClientToServer) {
        setCompressionMethodsClientToServer(compressionMethodsClientToServer, false);
    }

    public void setCompressionMethodsClientToServer(
            ModifiableString compressionMethodsClientToServer, boolean adjustLengthField) {
        this.compressionMethodsClientToServer = compressionMethodsClientToServer;
        if (adjustLengthField) {
            setCompressionMethodsClientToServerLength(
                    this.compressionMethodsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setCompressionMethodsClientToServer(
            String compressionMethodsClientToServer, boolean adjustLengthField) {
        this.compressionMethodsClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsClientToServer, compressionMethodsClientToServer);
        if (adjustLengthField) {
            setCompressionMethodsClientToServerLength(
                    this.compressionMethodsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyCompressionMethodsClientToServer(
            String compressionMethodsClientToServer, boolean adjustLengthField, Config config) {
        if (this.compressionMethodsClientToServer == null
                || this.compressionMethodsClientToServer.getOriginalValue() == null) {
            this.compressionMethodsClientToServer =
                    ModifiableVariableFactory.safelySetValue(
                            this.compressionMethodsClientToServer,
                            compressionMethodsClientToServer);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || compressionMethodsClientToServerLength == null
                    || compressionMethodsClientToServerLength.getOriginalValue() == null) {
                setCompressionMethodsClientToServerLength(
                        this.compressionMethodsClientToServer
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setCompressionMethodsClientToServer(
            String[] compressionMethodsClientToServer, boolean adjustLengthField) {
        String nameList =
                String.join(
                        "" + CharConstants.ALGORITHM_SEPARATOR, compressionMethodsClientToServer);
        setCompressionMethodsClientToServer(nameList, adjustLengthField);
    }

    public void setCompressionMethodsClientToServer(
            List<CompressionMethod> compressionMethodsClientToServer, boolean adjustLengthField) {
        String nameList =
                compressionMethodsClientToServer.stream()
                        .map(CompressionMethod::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setCompressionMethodsClientToServer(nameList, adjustLengthField);
    }

    public ModifiableInteger getCompressionMethodsServerToClientLength() {
        return compressionMethodsServerToClientLength;
    }

    public void setCompressionMethodsServerToClientLength(
            ModifiableInteger compressionMethodsServerToClientLength) {
        this.compressionMethodsServerToClientLength = compressionMethodsServerToClientLength;
    }

    public void setCompressionMethodsServerToClientLength(
            int compressionMethodsServerToClientLength) {
        this.compressionMethodsServerToClientLength =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsServerToClientLength,
                        compressionMethodsServerToClientLength);
    }

    public ModifiableString getCompressionMethodsServerToClient() {
        return compressionMethodsServerToClient;
    }

    public void setCompressionMethodsServerToClient(
            ModifiableString compressionMethodsServerToClient) {
        setCompressionMethodsServerToClient(compressionMethodsServerToClient, false);
    }

    public void setCompressionMethodsServerToClient(String compressionMethodsServerToClient) {
        setCompressionMethodsServerToClient(compressionMethodsServerToClient, false);
    }

    public void setCompressionMethodsServerToClient(String[] compressionMethodsServerToClient) {
        setCompressionMethodsServerToClient(compressionMethodsServerToClient, false);
    }

    public void setCompressionMethodsServerToClient(
            List<CompressionMethod> compressionMethodsServerToClient) {
        setCompressionMethodsServerToClient(compressionMethodsServerToClient, false);
    }

    public void setCompressionMethodsServerToClient(
            ModifiableString compressionMethodsServerToClient, boolean adjustLengthField) {
        this.compressionMethodsServerToClient = compressionMethodsServerToClient;
        if (adjustLengthField) {
            setCompressionMethodsServerToClientLength(
                    this.compressionMethodsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setCompressionMethodsServerToClient(
            String compressionMethodsServerToClient, boolean adjustLengthField) {
        this.compressionMethodsServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsServerToClient, compressionMethodsServerToClient);
        if (adjustLengthField) {
            setCompressionMethodsServerToClientLength(
                    this.compressionMethodsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyCompressionMethodsServerToClient(
            String compressionMethodsServerToClient, boolean adjustLengthField, Config config) {
        if (this.compressionMethodsServerToClient == null
                || this.compressionMethodsServerToClient.getOriginalValue() == null) {
            this.compressionMethodsServerToClient =
                    ModifiableVariableFactory.safelySetValue(
                            this.compressionMethodsServerToClient,
                            compressionMethodsServerToClient);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || compressionMethodsServerToClientLength == null
                    || compressionMethodsServerToClientLength.getOriginalValue() == null) {
                setCompressionMethodsServerToClientLength(
                        this.compressionMethodsServerToClient
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setCompressionMethodsServerToClient(
            String[] compressionMethodsServerToClient, boolean adjustLengthField) {
        String nameList =
                String.join(
                        "" + CharConstants.ALGORITHM_SEPARATOR, compressionMethodsServerToClient);
        setCompressionMethodsServerToClient(nameList, adjustLengthField);
    }

    public void setCompressionMethodsServerToClient(
            List<CompressionMethod> compressionMethodsServerToClient, boolean adjustLengthField) {
        String nameList =
                compressionMethodsServerToClient.stream()
                        .map(CompressionMethod::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setCompressionMethodsServerToClient(nameList, adjustLengthField);
    }

    public ModifiableInteger getLanguagesClientToServerLength() {
        return languagesClientToServerLength;
    }

    public void setLanguagesClientToServerLength(ModifiableInteger languagesClientToServerLength) {
        this.languagesClientToServerLength = languagesClientToServerLength;
    }

    public void setLanguagesClientToServerLength(int languagesClientToServerLength) {
        this.languagesClientToServerLength =
                ModifiableVariableFactory.safelySetValue(
                        this.languagesClientToServerLength, languagesClientToServerLength);
    }

    public ModifiableString getLanguagesClientToServer() {
        return languagesClientToServer;
    }

    public void setLanguagesClientToServer(ModifiableString languagesClientToServer) {
        setLanguagesClientToServer(languagesClientToServer, false);
    }

    public void setLanguagesClientToServer(String languagesClientToServer) {
        setLanguagesClientToServer(languagesClientToServer, false);
    }

    public void setLanguagesClientToServer(String[] languagesClientToServer) {
        setLanguagesClientToServer(languagesClientToServer, false);
    }

    public void setLanguagesClientToServer(
            ModifiableString languagesClientToServer, boolean adjustLengthField) {
        this.languagesClientToServer = languagesClientToServer;
        if (adjustLengthField) {
            setLanguagesClientToServerLength(
                    this.languagesClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setLanguagesClientToServer(
            String languagesClientToServer, boolean adjustLengthField) {
        this.languagesClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.languagesClientToServer, languagesClientToServer);
        if (adjustLengthField) {
            setLanguagesClientToServerLength(
                    this.languagesClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyLanguagesClientToServer(
            String languagesClientToServer, boolean adjustLengthField, Config config) {
        if (this.languagesClientToServer == null
                || this.languagesClientToServer.getOriginalValue() == null) {
            this.languagesClientToServer =
                    ModifiableVariableFactory.safelySetValue(
                            this.languagesClientToServer, languagesClientToServer);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || languagesClientToServerLength == null
                    || languagesClientToServerLength.getOriginalValue() == null) {
                setLanguagesClientToServerLength(
                        this.languagesClientToServer
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setLanguagesClientToServer(
            String[] languagesClientToServer, boolean adjustLengthField) {
        String nameList =
                String.join("" + CharConstants.ALGORITHM_SEPARATOR, languagesClientToServer);
        setLanguagesClientToServer(nameList, adjustLengthField);
    }

    public ModifiableInteger getLanguagesServerToClientLength() {
        return languagesServerToClientLength;
    }

    public void setLanguagesServerToClientLength(ModifiableInteger languagesServerToClientLength) {
        this.languagesServerToClientLength = languagesServerToClientLength;
    }

    public void setLanguagesServerToClientLength(int languagesServerToClientLength) {
        this.languagesServerToClientLength =
                ModifiableVariableFactory.safelySetValue(
                        this.languagesServerToClientLength, languagesServerToClientLength);
    }

    public ModifiableString getLanguagesServerToClient() {
        return languagesServerToClient;
    }

    public void setLanguagesServerToClient(ModifiableString languagesServerToClient) {
        setLanguagesServerToClient(languagesServerToClient, false);
    }

    public void setLanguagesServerToClient(String languagesServerToClient) {
        setLanguagesServerToClient(languagesServerToClient, false);
    }

    public void setLanguagesServerToClient(String[] languagesServerToClient) {
        setLanguagesServerToClient(languagesServerToClient, false);
    }

    public void setLanguagesServerToClient(
            ModifiableString languagesServerToClient, boolean adjustLengthField) {
        this.languagesServerToClient = languagesServerToClient;
        if (adjustLengthField) {
            setLanguagesServerToClientLength(
                    this.languagesServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setLanguagesServerToClient(
            String languagesServerToClient, boolean adjustLengthField) {
        this.languagesServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.languagesServerToClient, languagesServerToClient);
        if (adjustLengthField) {
            setLanguagesServerToClientLength(
                    this.languagesServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyLanguagesServerToClient(
            String languagesServerToClient, boolean adjustLengthField, Config config) {
        if (this.languagesServerToClient == null
                || this.languagesServerToClient.getOriginalValue() == null) {
            this.languagesServerToClient =
                    ModifiableVariableFactory.safelySetValue(
                            this.languagesServerToClient, languagesServerToClient);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || languagesServerToClientLength == null
                    || languagesServerToClientLength.getOriginalValue() == null) {
                setLanguagesServerToClientLength(
                        this.languagesServerToClient
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setLanguagesServerToClient(
            String[] languagesServerToClient, boolean adjustLengthField) {
        String nameList =
                String.join("" + CharConstants.ALGORITHM_SEPARATOR, languagesServerToClient);
        setLanguagesServerToClient(nameList, adjustLengthField);
    }

    public ModifiableByte getFirstKeyExchangePacketFollows() {
        return firstKeyExchangePacketFollows;
    }

    public void setFirstKeyExchangePacketFollows(ModifiableByte firstKeyExchangePacketFollows) {
        this.firstKeyExchangePacketFollows = firstKeyExchangePacketFollows;
    }

    public void setFirstKeyExchangePacketFollows(byte firstKeyExchangePacketFollows) {
        this.firstKeyExchangePacketFollows =
                ModifiableVariableFactory.safelySetValue(
                        this.firstKeyExchangePacketFollows, firstKeyExchangePacketFollows);
    }

    public void setSoftlyFirstKeyExchangePacketFollows(byte firstKeyExchangePacketFollows) {
        if (this.firstKeyExchangePacketFollows == null
                || this.firstKeyExchangePacketFollows.getOriginalValue() == null) {
            this.firstKeyExchangePacketFollows =
                    ModifiableVariableFactory.safelySetValue(
                            this.firstKeyExchangePacketFollows, firstKeyExchangePacketFollows);
        }
    }

    public void setFirstKeyExchangePacketFollows(boolean firstKeyExchangePacketFollows) {
        this.firstKeyExchangePacketFollows =
                ModifiableVariableFactory.safelySetValue(
                        this.firstKeyExchangePacketFollows,
                        Converter.booleanToByte(firstKeyExchangePacketFollows));
    }

    public ModifiableInteger getReserved() {
        return reserved;
    }

    public void setReserved(ModifiableInteger reserved) {
        this.reserved = reserved;
    }

    public void setReserved(int reserved) {
        this.reserved = ModifiableVariableFactory.safelySetValue(this.reserved, reserved);
    }

    public void setSoftlyReserved(int reserved) {
        if (this.reserved == null || this.reserved.getOriginalValue() == null) {
            this.reserved = ModifiableVariableFactory.safelySetValue(this.reserved, reserved);
        }
    }

    @Override
    public KeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new KeyExchangeInitMessageHandler(context, this);
    }
}
