/*
 * Copyright (c) 2021 Björn Raupach
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

package org.myoauth;

import org.junit.jupiter.api.Test;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

class CryptoblockTest {

    private Cryptoblock cryptoblock = Cryptoblock.getInstance();

    @Test
    public void areEqual() {
        assertFalse(cryptoblock.areEqual(null, "something"));
        assertFalse(cryptoblock.areEqual("something", null));
        assertFalse(cryptoblock.areEqual(null, null));
        assertFalse(cryptoblock.areEqual("something", "else"));
        assertFalse(cryptoblock.areEqual("something", "SOMETHING"));

        assertTrue(cryptoblock.areEqual("something", "something"));
    }

    @Test
    public void areNotEqual() {
        assertTrue(cryptoblock.areNotEqual(null, "something"));
        assertTrue(cryptoblock.areNotEqual("something", null));
        assertTrue(cryptoblock.areNotEqual(null, null));
        assertTrue(cryptoblock.areNotEqual("something", "else"));
        assertTrue(cryptoblock.areNotEqual("something", "SOMETHING"));

        assertFalse(cryptoblock.areNotEqual("something", "something"));
    }

    @Test
    public void randomString() {
        cryptoblock.random(16);

    }

    @Test
    public void randomStringThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> cryptoblock.random(-1));
    }

    @Test
    public void base64UrlEncode() {
        byte[] src = new byte[]{};
        String encoded = cryptoblock.base64UrlEncode(src);
        assertThat(encoded, is(""));

        src = new byte[] { 0x61, 0x73, 0x64, 0x66 };
        encoded = cryptoblock.base64UrlEncode(src);
        assertThat(encoded, is("YXNkZg"));
    }

    @Test
    public void base64UrlDecode() {
        String src = "";
        byte[] decoded = cryptoblock.base64UrlDecode(src);
        assertThat(decoded, is(new byte[]{}));

        src = "YXNkZg";
        decoded = cryptoblock.base64UrlDecode(src);
        assertThat(decoded, is(new byte[] { 0x61, 0x73, 0x64, 0x66 }));
    }



}