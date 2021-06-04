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


import static java.util.Objects.nonNull;

/**
 * Provides a more functional way of exception handling. Instead of throwing an
 * exception, we return either an error object or the expected value.
 * Left is usually the exception case and right is expected value.
 */
public class Either<L, R> {

    private final L left;
    private final R right;

    private Either(L left, R right) {
        this.left = left;
        this.right = right;
    }

    public L getLeft() {
        if (left == null) {
            throw new NullPointerException();
        }
        return left;
    }

    public boolean isLeft() {
        return nonNull(left);
    }

    public R getRight() {
        if (right == null) {
            throw new NullPointerException();
        }
        return right;
    }

    public boolean isRight() {
        return nonNull(right);
    }

    public static <L,R> Either<L, R> ofRight(R value) {
        return new Either(null, value);
    }

    public static <L,R>  Either<L, R> ofLeft(L value) {
        return new Either(value, null);
    }


}
