/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp;

import de.rub.nds.sshattacker.core.constants.SftpStatusCode;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.*;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.*;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.*;
import de.rub.nds.sshattacker.core.data.sftp.common.message.response.*;
import de.rub.nds.sshattacker.core.exceptions.DataManagerException;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpManager {

    private static final Logger LOGGER = LogManager.getLogger();

    // Requests that wait for a response
    private final HashMap<Integer, SftpRequestMessage<?>> pendingRequests = new HashMap<>();

    private final SshContext context;

    // Responses created as reaction to received requests; that wait to be sent
    private final List<SftpResponseMessage<?>> pendingResponses = new ArrayList<>();

    private final List<byte[]> openFileHandles = new ArrayList<>();
    private final List<byte[]> openDirectoryHandles = new ArrayList<>();

    private int lastUsedRequestId = -1;

    private static final Random random = new Random();

    public SftpManager(SshContext context) {
        super();
        this.context = context;
    }

    public int getNextRequestId() {
        lastUsedRequestId += 1;
        return lastUsedRequestId;
    }

    public void handleRequestMessage(SftpRequestMessage<?> request) {
        // prepare the response and queue it
        SftpResponseMessage<?> response;
        boolean sucess = random.nextBoolean();
        if (!sucess) {
            response = new SftpResponseStatusMessage();
            ((SftpResponseStatusMessage) response).setStatusCode(SftpStatusCode.SSH_FX_FAILURE);
        } else if (request instanceof SftpRequestOpenMessage) {
            response = new SftpResponseHandleMessage();
            ((SftpResponseHandleMessage) response).setHandle(createFileHandle());
        } else if (request instanceof SftpRequestOpenDirMessage) {
            response = new SftpResponseHandleMessage();
            ((SftpResponseHandleMessage) response).setHandle(createDirectoryHandle());
        } else if (request instanceof SftpRequestReadMessage) {
            response = new SftpResponseDataMessage();
        } else if (request instanceof SftpRequestReadDirMessage
                || request instanceof SftpRequestReadLinkMessage
                || request instanceof SftpRequestRealPathMessage
                || request instanceof SftpRequestHomeDirectoryMessage
                || request instanceof SftpRequestGetTempFolderMessage
                || request instanceof SftpRequestMakeTempFolderMessage
                || request instanceof SftpRequestExpandPathMessage) {
            response = new SftpResponseNameMessage();
        } else if (request instanceof SftpRequestStatMessage
                || request instanceof SftpRequestFileStatMessage
                || request instanceof SftpRequestLinkStatMessage) {
            response = new SftpResponseAttributesMessage();
        } else if (request instanceof SftpRequestCheckFileHandleMessage
                || request instanceof SftpRequestCheckFileNameMessage) {
            response = new SftpResponseCheckFileMessage();
        } else if (request instanceof SftpRequestSpaceAvailableMessage) {
            response = new SftpResponseSpaceAvailableMessage();
        } else if (request instanceof SftpRequestStatVfsMessage
                || request instanceof SftpRequestFileStatVfsMessage) {
            response = new SftpResponseStatVfsMessage();
        } else if (request instanceof SftpRequestLimitsMessage) {
            response = new SftpResponseLimitsMessage();
        } else if (request instanceof SftpRequestUsersGroupsByIdMessage) {
            response = new SftpResponseUsersGroupsByIdMessage();
        } else {
            /* Messages without special response:
            - SSH_FXP_CLOSE, SSH_FXP_WRITE, SSH_FXP_REMOVE, SSH_FXP_RENAME, SSH_FXP_MKDIR
            - SSH_FXP_RMDIR, SSH_FXP_SETSTAT, SSH_FXP_FSETSTAT, SSH_FXP_SYMLINK
            - vendor-id, copy-file, copy-data
            - posix-rename, hardlink, fsync, lsetstat,
            - text-seek
             */
            response = new SftpResponseStatusMessage();
            ((SftpResponseStatusMessage) response).setStatusCode(SftpStatusCode.SSH_FX_OK);
        }
        response.setRequestId(request.getRequestId());
        pendingResponses.add(response);
    }

    public SftpResponseMessage<?> prepareNextResponse() {
        if (!pendingResponses.isEmpty()) {
            return pendingResponses.remove(random.nextInt(pendingResponses.size()));
        }
        SftpResponseMessage<?> randomResponse;
        int responseType = random.nextInt(11);
        switch (responseType) {
            case 0:
                randomResponse = new SftpResponseStatusMessage();
                ((SftpResponseStatusMessage) randomResponse)
                        .setStatusCode(SftpStatusCode.SSH_FX_FAILURE);
                break;
            case 1:
                randomResponse = new SftpResponseHandleMessage();
                break;
            case 2:
                randomResponse = new SftpResponseDataMessage();
                break;
            case 3:
                randomResponse = new SftpResponseNameMessage();
                break;
            case 4:
                randomResponse = new SftpResponseAttributesMessage();
                break;
            case 5:
                randomResponse = new SftpResponseCheckFileMessage();
                break;
            case 6:
                randomResponse = new SftpResponseSpaceAvailableMessage();
                break;
            case 7:
                randomResponse = new SftpResponseStatVfsMessage();
                break;
            case 8:
                randomResponse = new SftpResponseLimitsMessage();
                break;
            case 9:
                randomResponse = new SftpResponseUsersGroupsByIdMessage();
                break;
            case 10:
            default:
                randomResponse = new SftpResponseStatusMessage();
                ((SftpResponseStatusMessage) randomResponse)
                        .setStatusCode(SftpStatusCode.SSH_FX_OK);
                break;
        }

        return randomResponse;
    }

    public SftpRequestMessage<?> getRequestById(Integer requestId) {
        return pendingRequests.get(requestId);
    }

    public SftpRequestMessage<?> removeRequestById(Integer requestId) {
        return pendingRequests.remove(requestId);
    }

    public boolean containsRequestWithId(Integer requestId) {
        return pendingRequests.containsKey(requestId);
    }

    public int countRequests() {
        return pendingRequests.size();
    }

    public void addRequest(SftpRequestMessage<?> request) {
        Integer requestId = request.getRequestId().getValue();
        if (requestId == null) {
            throw new DataManagerException(
                    "Request cannot be managed. Request identifier is not set");
        }
        pendingRequests.put(requestId, request);
    }

    private static byte[] getRandomHandle() {
        byte[] handle = new byte[random.nextInt(256) + 1];
        random.nextBytes(handle);
        return handle;
    }

    private byte[] createFileHandle() {
        byte[] handle = getRandomHandle();
        openFileHandles.add(handle);
        return handle;
    }

    private byte[] createDirectoryHandle() {
        byte[] handle = getRandomHandle();
        openDirectoryHandles.add(handle);
        return handle;
    }

    /**
     * Return a known valid directory handle that has the specified index in the maintained list.
     * The specified index is always calculated modulo the list size.
     *
     * <p>If index is null, return a random valid directory handle instead
     *
     * <p>If there are no valid handles, return an invalid random handle.
     *
     * @return handle
     */
    public byte[] getDirectoryHandle(Integer index) {
        if (!openDirectoryHandles.isEmpty()) {
            if (index != null) {
                return openDirectoryHandles.get(index % openDirectoryHandles.size());
            }
            return openDirectoryHandles.get(random.nextInt(openDirectoryHandles.size()));
        }
        LOGGER.debug("No directory handle availible, creating an invalid random handle");
        return getRandomHandle();
    }

    /**
     * Return a known valid file handle that has the specified index in the maintained list. The
     * specified index is always calculated modulo the list size.
     *
     * <p>If index is null, return a random valid file handle instead
     *
     * <p>If there are no valid handles, return an invalid random handle.
     *
     * @return handle
     */
    public byte[] getFileHandle(Integer index) {
        if (!openFileHandles.isEmpty()) {
            if (index != null) {
                return openFileHandles.get(index % openFileHandles.size());
            }
            return openFileHandles.get(random.nextInt(openFileHandles.size()));
        }
        LOGGER.debug("No file handle availible, creating an invalid random handle");
        return getRandomHandle();
    }

    /**
     * Return a known valid file or directory handle that has the specified index in the maintained
     * list. The specified index is always calculated modulo the combined list size.
     *
     * <p>If index is null, return a random valid file or directory handle instead
     *
     * <p>If there are no valid handles, return an invalid random handle.
     *
     * @return handle
     */
    public byte[] getFileOrDirectoryHandle(Integer index) {
        if (!openFileHandles.isEmpty() || !openDirectoryHandles.isEmpty()) {
            int resultIdx;
            if (index != null) {
                resultIdx = index % (openFileHandles.size() + openDirectoryHandles.size());
            } else {
                resultIdx = random.nextInt(openFileHandles.size() + openDirectoryHandles.size());
            }
            if (resultIdx >= openFileHandles.size()) {
                resultIdx -= openFileHandles.size();
                return openDirectoryHandles.get(resultIdx);
            }
            return openFileHandles.get(resultIdx);
        }
        LOGGER.debug("No handle availible, creating an invalid random handle");
        return getRandomHandle();
    }

    public void addHandle(SftpResponseHandleMessage handleMessage) {
        SftpRequestMessage<?> request =
                pendingRequests.get(handleMessage.getRequestId().getValue());
        if (request instanceof SftpRequestOpenDirMessage) {
            openDirectoryHandles.add(handleMessage.getHandle().getValue());
        } else if (request instanceof SftpRequestOpenMessage) {
            openFileHandles.add(handleMessage.getHandle().getValue());
        } else {
            LOGGER.warn(
                    "Tried to add handle from response that is not a response to a SSH_FXP_OPEN or SSH_FXP_OPENDIR request. Ignoring it.");
        }
    }
}
