/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
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
    private ModifiableInteger compressionAlgorithmsClientToServerLength;
    private ModifiableString compressionAlgorithmsClientToServer;
    private ModifiableInteger compressionAlgorithmsServerToClientLength;
    private ModifiableString compressionAlgorithmsServerToClient;
    private ModifiableInteger languagesClientToServerLength;
    private ModifiableString languagesClientToServer;
    private ModifiableInteger languagesServerToClientLength;
    private ModifiableString languagesServerToClient;
    private ModifiableByte firstKeyExchangePacketFollows;
    private ModifiableInteger reserved;

    public KeyExchangeInitMessage() {
        super(MessageIDConstant.SSH_MSG_KEXINIT);
    }

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
        if (adjustLengthField) {
            setKeyExchangeAlgorithmsLength(
                    keyExchangeAlgorithms.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.keyExchangeAlgorithms = keyExchangeAlgorithms;
    }

    public void setKeyExchangeAlgorithms(String keyExchangeAlgorithms, boolean adjustLengthField) {
        if (adjustLengthField) {
            setKeyExchangeAlgorithmsLength(
                    keyExchangeAlgorithms.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.keyExchangeAlgorithms =
                ModifiableVariableFactory.safelySetValue(
                        this.keyExchangeAlgorithms, keyExchangeAlgorithms);
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

    public void setServerHostKeyAlgorithms(
            List<PublicKeyAuthenticationAlgorithm> serverHostKeyAlgorithms) {
        setServerHostKeyAlgorithms(serverHostKeyAlgorithms, false);
    }

    public void setServerHostKeyAlgorithms(
            ModifiableString serverHostKeyAlgorithms, boolean adjustLengthField) {
        if (adjustLengthField) {
            setServerHostKeyAlgorithmsLength(
                    serverHostKeyAlgorithms.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.serverHostKeyAlgorithms = serverHostKeyAlgorithms;
    }

    public void setServerHostKeyAlgorithms(
            String serverHostKeyAlgorithms, boolean adjustLengthField) {
        if (adjustLengthField) {
            setServerHostKeyAlgorithmsLength(
                    serverHostKeyAlgorithms.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.serverHostKeyAlgorithms =
                ModifiableVariableFactory.safelySetValue(
                        this.serverHostKeyAlgorithms, serverHostKeyAlgorithms);
    }

    public void setServerHostKeyAlgorithms(
            String[] serverHostKeyAlgorithms, boolean adjustLengthField) {
        String nameList =
                String.join("" + CharConstants.ALGORITHM_SEPARATOR, serverHostKeyAlgorithms);
        setServerHostKeyAlgorithms(nameList, adjustLengthField);
    }

    public void setServerHostKeyAlgorithms(
            List<PublicKeyAuthenticationAlgorithm> serverHostKeyAlgorithms,
            boolean adjustLengthField) {
        String nameList =
                serverHostKeyAlgorithms.stream()
                        .map(PublicKeyAuthenticationAlgorithm::toString)
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
        if (adjustLengthField) {
            setEncryptionAlgorithmsClientToServerLength(
                    encryptionAlgorithmsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
        this.encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer;
    }

    public void setEncryptionAlgorithmsClientToServer(
            String encryptionAlgorithmsClientToServer, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEncryptionAlgorithmsClientToServerLength(
                    encryptionAlgorithmsClientToServer.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.encryptionAlgorithmsClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptionAlgorithmsClientToServer,
                        encryptionAlgorithmsClientToServer);
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
        if (adjustLengthField) {
            setEncryptionAlgorithmsServerToClientLength(
                    encryptionAlgorithmsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
        this.encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient;
    }

    public void setEncryptionAlgorithmsServerToClient(
            String encryptionAlgorithmsServerToClient, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEncryptionAlgorithmsServerToClientLength(
                    encryptionAlgorithmsServerToClient.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.encryptionAlgorithmsServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptionAlgorithmsServerToClient,
                        encryptionAlgorithmsServerToClient);
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
        if (adjustLengthField) {
            setMacAlgorithmsClientToServerLength(
                    macAlgorithmsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
        this.macAlgorithmsClientToServer = macAlgorithmsClientToServer;
    }

    public void setMacAlgorithmsClientToServer(
            String macAlgorithmsClientToServer, boolean adjustLengthField) {
        if (adjustLengthField) {
            setMacAlgorithmsClientToServerLength(
                    macAlgorithmsClientToServer.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.macAlgorithmsClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.macAlgorithmsClientToServer, macAlgorithmsClientToServer);
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
        if (adjustLengthField) {
            setMacAlgorithmsServerToClientLength(
                    macAlgorithmsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
        this.macAlgorithmsServerToClient = macAlgorithmsServerToClient;
    }

    public void setMacAlgorithmsServerToClient(
            String macAlgorithmsServerToClient, boolean adjustLengthField) {
        if (adjustLengthField) {
            setMacAlgorithmsServerToClientLength(
                    macAlgorithmsServerToClient.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.macAlgorithmsServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.macAlgorithmsServerToClient, macAlgorithmsServerToClient);
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

    public ModifiableInteger getCompressionAlgorithmsClientToServerLength() {
        return compressionAlgorithmsClientToServerLength;
    }

    public void setCompressionAlgorithmsClientToServerLength(
            ModifiableInteger compressionAlgorithmsClientToServerLength) {
        this.compressionAlgorithmsClientToServerLength = compressionAlgorithmsClientToServerLength;
    }

    public void setCompressionAlgorithmsClientToServerLength(
            int compressionAlgorithmsClientToServerLength) {
        this.compressionAlgorithmsClientToServerLength =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionAlgorithmsClientToServerLength,
                        compressionAlgorithmsClientToServerLength);
    }

    public ModifiableString getCompressionAlgorithmsClientToServer() {
        return compressionAlgorithmsClientToServer;
    }

    public void setCompressionAlgorithmsClientToServer(
            ModifiableString compressionAlgorithmsClientToServer) {
        setCompressionAlgorithmsClientToServer(compressionAlgorithmsClientToServer, false);
    }

    public void setCompressionAlgorithmsClientToServer(String compressionAlgorithmsClientToServer) {
        setCompressionAlgorithmsClientToServer(compressionAlgorithmsClientToServer, false);
    }

    public void setCompressionAlgorithmsClientToServer(
            String[] compressionAlgorithmsClientToServer) {
        setCompressionAlgorithmsClientToServer(compressionAlgorithmsClientToServer, false);
    }

    public void setCompressionAlgorithmsClientToServer(
            List<CompressionAlgorithm> compressionAlgorithmsClientToServer) {
        setCompressionAlgorithmsClientToServer(compressionAlgorithmsClientToServer, false);
    }

    public void setCompressionAlgorithmsClientToServer(
            ModifiableString compressionAlgorithmsClientToServer, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCompressionAlgorithmsClientToServerLength(
                    compressionAlgorithmsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
        this.compressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer;
    }

    public void setCompressionAlgorithmsClientToServer(
            String compressionAlgorithmsClientToServer, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCompressionAlgorithmsClientToServerLength(
                    compressionAlgorithmsClientToServer.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.compressionAlgorithmsClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionAlgorithmsClientToServer,
                        compressionAlgorithmsClientToServer);
    }

    public void setCompressionAlgorithmsClientToServer(
            String[] compressionAlgorithmsClientToServer, boolean adjustLengthField) {
        String nameList =
                String.join(
                        "" + CharConstants.ALGORITHM_SEPARATOR,
                        compressionAlgorithmsClientToServer);
        setCompressionAlgorithmsClientToServer(nameList, adjustLengthField);
    }

    public void setCompressionAlgorithmsClientToServer(
            List<CompressionAlgorithm> compressionAlgorithmsClientToServer,
            boolean adjustLengthField) {
        String nameList =
                compressionAlgorithmsClientToServer.stream()
                        .map(CompressionAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setCompressionAlgorithmsClientToServer(nameList, adjustLengthField);
    }

    public ModifiableInteger getCompressionAlgorithmsServerToClientLength() {
        return compressionAlgorithmsServerToClientLength;
    }

    public void setCompressionAlgorithmsServerToClientLength(
            ModifiableInteger compressionAlgorithmsServerToClientLength) {
        this.compressionAlgorithmsServerToClientLength = compressionAlgorithmsServerToClientLength;
    }

    public void setCompressionAlgorithmsServerToClientLength(
            int compressionAlgorithmsServerToClientLength) {
        this.compressionAlgorithmsServerToClientLength =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionAlgorithmsServerToClientLength,
                        compressionAlgorithmsServerToClientLength);
    }

    public ModifiableString getCompressionAlgorithmsServerToClient() {
        return compressionAlgorithmsServerToClient;
    }

    public void setCompressionAlgorithmsServerToClient(
            ModifiableString compressionAlgorithmsServerToClient) {
        setCompressionAlgorithmsServerToClient(compressionAlgorithmsServerToClient, false);
    }

    public void setCompressionAlgorithmsServerToClient(String compressionAlgorithmsServerToClient) {
        setCompressionAlgorithmsServerToClient(compressionAlgorithmsServerToClient, false);
    }

    public void setCompressionAlgorithmsServerToClient(
            String[] compressionAlgorithmsServerToClient) {
        setCompressionAlgorithmsServerToClient(compressionAlgorithmsServerToClient, false);
    }

    public void setCompressionAlgorithmsServerToClient(
            List<CompressionAlgorithm> compressionAlgorithmsServerToClient) {
        setCompressionAlgorithmsServerToClient(compressionAlgorithmsServerToClient, false);
    }

    public void setCompressionAlgorithmsServerToClient(
            ModifiableString compressionAlgorithmsServerToClient, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCompressionAlgorithmsServerToClientLength(
                    compressionAlgorithmsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
        this.compressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient;
    }

    public void setCompressionAlgorithmsServerToClient(
            String compressionAlgorithmsServerToClient, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCompressionAlgorithmsServerToClientLength(
                    compressionAlgorithmsServerToClient.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.compressionAlgorithmsServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionAlgorithmsServerToClient,
                        compressionAlgorithmsServerToClient);
    }

    public void setCompressionAlgorithmsServerToClient(
            String[] compressionAlgorithmsServerToClient, boolean adjustLengthField) {
        String nameList =
                String.join(
                        "" + CharConstants.ALGORITHM_SEPARATOR,
                        compressionAlgorithmsServerToClient);
        setCompressionAlgorithmsServerToClient(nameList, adjustLengthField);
    }

    public void setCompressionAlgorithmsServerToClient(
            List<CompressionAlgorithm> compressionAlgorithmsServerToClient,
            boolean adjustLengthField) {
        String nameList =
                compressionAlgorithmsServerToClient.stream()
                        .map(CompressionAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setCompressionAlgorithmsServerToClient(nameList, adjustLengthField);
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
        if (adjustLengthField) {
            setLanguagesClientToServerLength(
                    languagesClientToServer.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.languagesClientToServer = languagesClientToServer;
    }

    public void setLanguagesClientToServer(
            String languagesClientToServer, boolean adjustLengthField) {
        if (adjustLengthField) {
            setLanguagesClientToServerLength(
                    languagesClientToServer.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.languagesClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.languagesClientToServer, languagesClientToServer);
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
        if (adjustLengthField) {
            setLanguagesServerToClientLength(
                    languagesServerToClient.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.languagesServerToClient = languagesServerToClient;
    }

    public void setLanguagesServerToClient(
            String languagesServerToClient, boolean adjustLengthField) {
        if (adjustLengthField) {
            setLanguagesServerToClientLength(
                    languagesServerToClient.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.languagesServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.languagesServerToClient, languagesServerToClient);
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

    @Override
    public KeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new KeyExchangeInitMessageHandler(context, this);
    }
}
