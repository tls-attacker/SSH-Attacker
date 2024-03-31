/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.RequestPtyMessageSSHv1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.RequestPtyMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.RequestPtyMessageSSHv1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.RequestPtyMessageSSHv1Serializier;
import java.io.InputStream;

public class RequestPtyMessageSSH1 extends Ssh1Message<RequestPtyMessageSSH1> {

    ModifiableString termEnvironment;
    ModifiableInteger hightRows;
    ModifiableInteger widthColumns;
    ModifiableInteger widthPixel;
    ModifiableInteger hightPixel;
    ModifiableInteger ttyModes;

    public ModifiableString getTermEnvironment() {
        return termEnvironment;
    }

    public void setTermEnvironment(ModifiableString termEnvironment) {
        this.termEnvironment = termEnvironment;
    }

    public void setTermEnvironment(String termEnvironment) {
        this.termEnvironment =
                ModifiableVariableFactory.safelySetValue(this.termEnvironment, termEnvironment);
    }

    public ModifiableInteger getHightRows() {
        return hightRows;
    }

    public void setHightRows(ModifiableInteger hightRows) {
        this.hightRows = hightRows;
    }

    public void setHightRows(int hightRows) {
        this.hightRows = ModifiableVariableFactory.safelySetValue(this.hightRows, hightRows);
    }

    public ModifiableInteger getWidthColumns() {
        return widthColumns;
    }

    public void setWidthColumns(ModifiableInteger widthColumns) {
        this.widthColumns = widthColumns;
    }

    public void setWidthColumns(int widthColumns) {
        this.widthColumns =
                ModifiableVariableFactory.safelySetValue(this.widthColumns, widthColumns);
    }

    public ModifiableInteger getWidthPixel() {
        return widthPixel;
    }

    public void setWidthPixel(ModifiableInteger widthPixel) {
        this.widthPixel = widthPixel;
    }

    public void setWidthPixel(int widthPixel) {
        this.widthPixel = ModifiableVariableFactory.safelySetValue(this.widthPixel, widthPixel);
    }

    public ModifiableInteger getHightPixel() {
        return hightPixel;
    }

    public void setHightPixel(ModifiableInteger hightPixel) {
        this.hightPixel = hightPixel;
    }

    public void setHightPixel(int hightPixel) {
        this.hightPixel = ModifiableVariableFactory.safelySetValue(this.hightPixel, hightPixel);
    }

    public ModifiableInteger getTtyModes() {
        return ttyModes;
    }

    public void setTtyModes(ModifiableInteger ttyModes) {
        this.ttyModes = ttyModes;
    }

    public void setTtyModes(int ttyModes) {
        this.ttyModes = ModifiableVariableFactory.safelySetValue(this.ttyModes, ttyModes);
    }

    @Override
    public RequestPtyMessageSSHv1Handler getHandler(SshContext context) {
        return new RequestPtyMessageSSHv1Handler(context);
    }

    @Override
    public Ssh1MessageParser<RequestPtyMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new RequestPtyMessageSSHv1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<RequestPtyMessageSSH1> getPreparator(SshContext context) {
        return new RequestPtyMessageSSHv1Preparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<RequestPtyMessageSSH1> getSerializer(SshContext context) {
        return new RequestPtyMessageSSHv1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_SMSG_SUCCESS";
    }
}
