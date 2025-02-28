/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.modifieablevariable.pth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.sshattacker.core.modifiablevariable.path.ModifiablePath;
import de.rub.nds.sshattacker.core.modifiablevariable.path.PathDeleteModification;
import de.rub.nds.sshattacker.core.modifiablevariable.path.PathInsertValueModification;
import org.junit.jupiter.api.Test;

public class PathModificationTest {

    @Test
    public void testInsert() {
        ModifiablePath nullPath = new ModifiablePath();
        nullPath.setModifications(new PathInsertValueModification("test", 2));
        assertNull(nullPath.getValue());

        ModifiablePath emptyPath = new ModifiablePath("");
        emptyPath.setModifications(new PathInsertValueModification("test", 0));
        assertEquals("test", emptyPath.getValue());
        emptyPath.setModifications(new PathInsertValueModification("test", 10));
        assertEquals("test", emptyPath.getValue());

        ModifiablePath simplePathLeadingSlash = new ModifiablePath("/this/is/a/path");
        simplePathLeadingSlash.setModifications(new PathInsertValueModification("test", 0));
        assertEquals("/test/this/is/a/path", simplePathLeadingSlash.getValue());
        simplePathLeadingSlash.setModifications(new PathInsertValueModification("test", 4));
        assertEquals("/this/is/a/path/test", simplePathLeadingSlash.getValue());
        simplePathLeadingSlash.setModifications(new PathInsertValueModification("test", 5));
        assertEquals("/test/this/is/a/path", simplePathLeadingSlash.getValue());
        simplePathLeadingSlash.setModifications(new PathInsertValueModification("test", 6));
        assertEquals("/this/test/is/a/path", simplePathLeadingSlash.getValue());
        simplePathLeadingSlash.setModifications(new PathInsertValueModification("test", 11));
        assertEquals("/this/test/is/a/path", simplePathLeadingSlash.getValue());

        ModifiablePath simplePathLeadingAndTrailingSlash = new ModifiablePath("/this/is/a/path/");
        simplePathLeadingAndTrailingSlash.setModifications(
                new PathInsertValueModification("test", 0));
        assertEquals("/test/this/is/a/path/", simplePathLeadingAndTrailingSlash.getValue());
        simplePathLeadingAndTrailingSlash.setModifications(
                new PathInsertValueModification("test", 4));
        assertEquals("/this/is/a/path/test/", simplePathLeadingAndTrailingSlash.getValue());
        simplePathLeadingAndTrailingSlash.setModifications(
                new PathInsertValueModification("test", 5));
        assertEquals("/test/this/is/a/path/", simplePathLeadingAndTrailingSlash.getValue());
        simplePathLeadingAndTrailingSlash.setModifications(
                new PathInsertValueModification("test", 6));
        assertEquals("/this/test/is/a/path/", simplePathLeadingAndTrailingSlash.getValue());
        simplePathLeadingAndTrailingSlash.setModifications(
                new PathInsertValueModification("test", 11));
        assertEquals("/this/test/is/a/path/", simplePathLeadingAndTrailingSlash.getValue());

        ModifiablePath simplePath = new ModifiablePath("this/is/a/path");
        simplePath.setModifications(new PathInsertValueModification("test", 0));
        assertEquals("test/this/is/a/path", simplePath.getValue());
        simplePath.setModifications(new PathInsertValueModification("test", 4));
        assertEquals("this/is/a/path/test", simplePath.getValue());
        simplePath.setModifications(new PathInsertValueModification("test", 5));
        assertEquals("test/this/is/a/path", simplePath.getValue());
        simplePath.setModifications(new PathInsertValueModification("test", 6));
        assertEquals("this/test/is/a/path", simplePath.getValue());
        simplePath.setModifications(new PathInsertValueModification("test", 11));
        assertEquals("this/test/is/a/path", simplePath.getValue());

        ModifiablePath simplePathTrailingSlash = new ModifiablePath("this/is/a/path/");
        simplePathTrailingSlash.setModifications(new PathInsertValueModification("test", 0));
        assertEquals("test/this/is/a/path/", simplePathTrailingSlash.getValue());
        simplePathTrailingSlash.setModifications(new PathInsertValueModification("test", 4));
        assertEquals("this/is/a/path/test/", simplePathTrailingSlash.getValue());
        simplePathTrailingSlash.setModifications(new PathInsertValueModification("test", 5));
        assertEquals("test/this/is/a/path/", simplePathTrailingSlash.getValue());
        simplePathTrailingSlash.setModifications(new PathInsertValueModification("test", 6));
        assertEquals("this/test/is/a/path/", simplePathTrailingSlash.getValue());
        simplePathTrailingSlash.setModifications(new PathInsertValueModification("test", 11));
        assertEquals("this/test/is/a/path/", simplePathTrailingSlash.getValue());

        ModifiablePath rootPath = new ModifiablePath("/");
        rootPath.setModifications(new PathInsertValueModification("test", 0));
        assertEquals("/test/", rootPath.getValue());
        rootPath.setModifications(new PathInsertValueModification("test", 2));
        assertEquals("/test/", rootPath.getValue());
        rootPath.setModifications(new PathInsertValueModification("test", 5));
        assertEquals("/test/", rootPath.getValue());
    }

    @Test
    public void testDelete() {
        ModifiablePath nullPath = new ModifiablePath();
        nullPath.setModifications(new PathDeleteModification(0, 1));
        assertNull(nullPath.getValue());

        ModifiablePath emptyPath = new ModifiablePath("");
        emptyPath.setModifications(new PathDeleteModification(0, 1));
        assertEquals("", emptyPath.getValue());
        emptyPath.setModifications(new PathDeleteModification(1, 10));
        assertEquals("", emptyPath.getValue());

        ModifiablePath simplePathLeadingSlash = new ModifiablePath("/this/is/a/path");
        simplePathLeadingSlash.setModifications(new PathDeleteModification(0, 0));
        assertEquals("/this/is/a/path", simplePathLeadingSlash.getValue());
        simplePathLeadingSlash.setModifications(new PathDeleteModification(4, 4));
        assertEquals("", simplePathLeadingSlash.getValue());
        simplePathLeadingSlash.setModifications(new PathDeleteModification(4, 1));
        assertEquals("/is/a/path", simplePathLeadingSlash.getValue());
        simplePathLeadingSlash.setModifications(new PathDeleteModification(5, 1));
        assertEquals("/this/a/path", simplePathLeadingSlash.getValue());
        simplePathLeadingSlash.setModifications(new PathDeleteModification(6, 1));
        assertEquals("/this/is/path", simplePathLeadingSlash.getValue());
        simplePathLeadingSlash.setModifications(new PathDeleteModification(11, 11));
        assertEquals("/this/is/a", simplePathLeadingSlash.getValue());

        ModifiablePath simplePathLeadingAndTrailingSlash = new ModifiablePath("/this/is/a/path/");
        simplePathLeadingAndTrailingSlash.setModifications(new PathDeleteModification(0, 0));
        assertEquals("/this/is/a/path/", simplePathLeadingAndTrailingSlash.getValue());
        simplePathLeadingAndTrailingSlash.setModifications(new PathDeleteModification(4, 4));
        assertEquals("/", simplePathLeadingAndTrailingSlash.getValue());
        simplePathLeadingAndTrailingSlash.setModifications(new PathDeleteModification(4, 1));
        assertEquals("/is/a/path/", simplePathLeadingAndTrailingSlash.getValue());
        simplePathLeadingAndTrailingSlash.setModifications(new PathDeleteModification(5, 1));
        assertEquals("/this/a/path/", simplePathLeadingAndTrailingSlash.getValue());
        simplePathLeadingAndTrailingSlash.setModifications(new PathDeleteModification(6, 1));
        assertEquals("/this/is/path/", simplePathLeadingAndTrailingSlash.getValue());
        simplePathLeadingAndTrailingSlash.setModifications(new PathDeleteModification(11, 11));
        assertEquals("/this/is/a/", simplePathLeadingAndTrailingSlash.getValue());

        ModifiablePath simplePath = new ModifiablePath("this/is/a/path");
        simplePath.setModifications(new PathDeleteModification(0, 0));
        assertEquals("this/is/a/path", simplePath.getValue());
        simplePath.setModifications(new PathDeleteModification(4, 4));
        assertEquals("", simplePath.getValue());
        simplePath.setModifications(new PathDeleteModification(4, 1));
        assertEquals("is/a/path", simplePath.getValue());
        simplePath.setModifications(new PathDeleteModification(5, 1));
        assertEquals("this/a/path", simplePath.getValue());
        simplePath.setModifications(new PathDeleteModification(6, 1));
        assertEquals("this/is/path", simplePath.getValue());
        simplePath.setModifications(new PathDeleteModification(11, 11));
        assertEquals("this/is/a", simplePath.getValue());

        ModifiablePath simplePathTrailingSlash = new ModifiablePath("this/is/a/path/");
        simplePathTrailingSlash.setModifications(new PathDeleteModification(0, 0));
        assertEquals("this/is/a/path/", simplePathTrailingSlash.getValue());
        simplePathTrailingSlash.setModifications(new PathDeleteModification(4, 4));
        assertEquals("", simplePathTrailingSlash.getValue());
        simplePathTrailingSlash.setModifications(new PathDeleteModification(4, 1));
        assertEquals("is/a/path/", simplePathTrailingSlash.getValue());
        simplePathTrailingSlash.setModifications(new PathDeleteModification(5, 1));
        assertEquals("this/a/path/", simplePathTrailingSlash.getValue());
        simplePathTrailingSlash.setModifications(new PathDeleteModification(6, 1));
        assertEquals("this/is/path/", simplePathTrailingSlash.getValue());
        simplePathTrailingSlash.setModifications(new PathDeleteModification(11, 11));
        assertEquals("this/is/a/", simplePathTrailingSlash.getValue());

        ModifiablePath rootPath = new ModifiablePath("/");
        rootPath.setModifications(new PathDeleteModification(0, 0));
        assertEquals("/", rootPath.getValue());
        rootPath.setModifications(new PathDeleteModification(2, 2));
        assertEquals("", rootPath.getValue());
        rootPath.setModifications(new PathDeleteModification(5, 5));
        assertEquals("", rootPath.getValue());
    }
}
