/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.modifiablevariable.path;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.Objects;

/** Modification that inserts path parts to the original value. */
@XmlRootElement
public class PathInsertValueModification extends VariableModification<String> {

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String insertValue;

    private int startPosition;

    public PathInsertValueModification() {
        super();
    }

    public PathInsertValueModification(String insertValue, int startPosition) {
        super();
        this.insertValue = insertValue;
        this.startPosition = startPosition;
    }

    public PathInsertValueModification(PathInsertValueModification other) {
        super(other);
        insertValue = other.insertValue;
        startPosition = other.startPosition;
    }

    @Override
    public PathInsertValueModification createCopy() {
        return new PathInsertValueModification(this);
    }

    @Override
    protected String modifyImplementationHook(String input) {
        return PathUtil.insertValueAsPathPart(input, insertValue, startPosition);
    }

    public String getInsertValue() {
        return insertValue;
    }

    public void setInsertValue(String insertValue) {
        this.insertValue = insertValue;
    }

    public int getStartPosition() {
        return startPosition;
    }

    public void setStartPosition(int startPosition) {
        this.startPosition = startPosition;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 31 * hash + Objects.hashCode(insertValue);
        hash = 31 * hash + startPosition;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        PathInsertValueModification other = (PathInsertValueModification) obj;
        if (startPosition != other.startPosition) {
            return false;
        }
        return Objects.equals(insertValue, other.insertValue);
    }

    @Override
    public String toString() {
        return "PathInsertValueModification{"
                + "insertValue='"
                + backslashEscapeString(insertValue)
                + '\''
                + ", startPosition="
                + startPosition
                + '}';
    }
}
