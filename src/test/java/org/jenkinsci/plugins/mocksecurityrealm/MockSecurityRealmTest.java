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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import hudson.security.UserMayOrMayNotExistException2;
import jenkins.model.IdStrategy;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

class MockSecurityRealmTest {
    
    private final MockSecurityRealm r = new MockSecurityRealm("alice admin\nbob dev\ncharlie qa\ndebbie admin qa", null, false,
            IdStrategy.CASE_INSENSITIVE, IdStrategy.CASE_INSENSITIVE);

    @Test
    void nonexistentGroup() {
        assertThrows(UsernameNotFoundException.class, () ->
            r.loadGroupByGroupname2("nonexistent", false));
    }

    @Test
    void getMembers() {
        assertEquals("[alice, debbie]", r.loadGroupByGroupname2("admin", true).getMembers().toString(), "The users found in the 'admin' group are not the ones expected");
        assertEquals("[bob]", r.loadGroupByGroupname2("dev", true).getMembers().toString(), "The users found in the 'dev' group are not the ones expected");
        assertEquals("[charlie, debbie]",r.loadGroupByGroupname2("qa", true).getMembers().toString(), "The users found in the 'qa' group are not the ones expected");
    }

    @Test
    void getMembersWithIdStrategy() {
        assertEquals("[alice, debbie]",r.loadGroupByGroupname2("ADMIN", true).getMembers().toString(), "Searching for 'ADMIN' users should have returned the 'admin' users as id strategy is CASE_INSENSITIVE");
        assertEquals("[bob]",r.loadGroupByGroupname2("dEv", true).getMembers().toString(), "Searching for 'dEv' users should have returned the 'dev' users as id strategy is CASE_INSENSITIVE");
        assertEquals("[charlie, debbie]",r.loadGroupByGroupname2("qA", true).getMembers().toString(), "Searching for 'qA' users should have return the 'admin' users as id strategy is CASE_INSENSITIVE");
    }

    @Test
    void getUserWithIdStrategy() {
        assertThat("Searching for 'Alice' should have returned the proper user as user id strategy is CASE_INSENSITIVE", r.loadUserByUsername2("alice").getUsername(), is(r.loadUserByUsername2("Alice").getUsername()));
    }

    @Test
    void outage() {
        r.outage();
        assertThrows(UserMayOrMayNotExistException2.class, () -> r.loadUserByUsername2("alice"));
        assertThrows(UserMayOrMayNotExistException2.class, () -> r.loadGroupByGroupname2("admin", false));
        assertThrows(UserMayOrMayNotExistException2.class, () -> r.authenticate2("alice", "alice"));
    }

}
