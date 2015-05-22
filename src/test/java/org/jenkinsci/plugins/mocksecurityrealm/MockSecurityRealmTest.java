/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins.mocksecurityrealm;

import hudson.security.SecurityRealm;
import jenkins.model.IdStrategy;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.junit.Test;
import static org.junit.Assert.*;

public class MockSecurityRealmTest {
    
    private final SecurityRealm r = new MockSecurityRealm("alice/wonder admin\nbob dev\ncharlie qa\ndebbie admin qa", null, false,
            IdStrategy.CASE_INSENSITIVE, IdStrategy.CASE_INSENSITIVE);

    @Test(expected=UsernameNotFoundException.class) public void nonexistentGroup() {
        r.loadGroupByGroupname("nonexistent");
    }
    
    @Test public void getMembers() {
        assertEquals("[alice, debbie]", r.loadGroupByGroupname("admin", true).getMembers().toString());
        assertEquals("[bob]", r.loadGroupByGroupname("dev", true).getMembers().toString());
        assertEquals("[charlie, debbie]", r.loadGroupByGroupname("qa", true).getMembers().toString());
    }

    @Test public void verifyUserWithPassword() {
        assertEquals("wonder", r.loadUserByUsername("alice").getPassword());
    }

    @Test public void verifyUserWithoutPassword() {
        assertEquals("bob", r.loadUserByUsername("bob").getPassword());
    }

}