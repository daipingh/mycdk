/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"

TEST_DECLARE(fail_always)
TEST_DECLARE(pass_always)
TEST_DECLARE(platform_output)

TEST_DECLARE(hello)

//HELPER_DECLARE(tcp4_echo_server)
//HELPER_DECLARE(tcp6_echo_server)
//HELPER_DECLARE(udp4_echo_server)
//HELPER_DECLARE(pipe_echo_server)

TASK_LIST_START
	//TEST_ENTRY_CUSTOM (platform_output, 0, 1, 5000)

	TEST_ENTRY(hello)

#if 0
	/* These are for testing the test runner. */
	TEST_ENTRY  (fail_always)
	TEST_ENTRY  (pass_always)
#endif
TASK_LIST_END
