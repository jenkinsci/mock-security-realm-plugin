package org.jenkinsci.plugins.mocksecurityrealm;

import jenkins.model.Jenkins;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.junit.Rule;
import org.junit.Test;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import sun.security.krb5.Realm;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class MockSecurityRealmCascTest {

    @Rule public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

    @ConfiguredWithCode("realm-config.yml")
    @Test public void realmIsConfigured() {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        assertEquals("The users found in the 'admin' group are not the ones expected","[alice, debbie]", securityRealm.loadGroupByGroupname("admin", true).getMembers().toString());
        assertEquals("The users found in the 'dev' group are not the ones expected","[bob]", securityRealm.loadGroupByGroupname("dev", true).getMembers().toString());
        assertEquals("The users found in the 'qa' group are not the ones expected","[charlie, debbie]", securityRealm.loadGroupByGroupname("qa", true).getMembers().toString());

        assertEquals("Searching for 'ADMIN' users should have returned the 'admin' users as id strategy is CASE_INSENSITIVE", "[alice, debbie]", securityRealm.loadGroupByGroupname("ADMIN", true).getMembers().toString());
        assertEquals("Searching for 'dEv' users should have returned the 'dev' users as id strategy is CASE_INSENSITIVE","[bob]", securityRealm.loadGroupByGroupname("dEv", true).getMembers().toString());
        assertEquals("Searching for 'qA' users should have return the 'admin' users as id strategy is CASE_INSENSITIVE", "[charlie, debbie]", securityRealm.loadGroupByGroupname("qA", true).getMembers().toString());

        assertThat("Searching for 'Alice' should have returned the proper user as user id strategy is CASE_INSENSITIVE", securityRealm.loadUserByUsername("alice").getUsername(), is(securityRealm.loadUserByUsername("Alice").getUsername()));
    }

    @ConfiguredWithCode("realm-config-case-sensitive.yml")
    @Test public void realmIsConfiguredCaseSensitive() {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        assertEquals("The users in the 'ADMIN' group are not the expected as id strategy is CASE_SENSITIVE", "[Richard]", securityRealm.loadGroupByGroupname("ADMIN", true).getMembers().toString());
    }

    @ConfiguredWithCode("realm-config-case-sensitive.yml")
    @Test(expected= UsernameNotFoundException.class) public void userNameIsCaseSensitive() {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        securityRealm.loadUserByUsername("richard").getUsername();
    }

    private MockSecurityRealm getMockSecurityRealm() {
        final Jenkins jenkins = Jenkins.get();
        return (MockSecurityRealm) jenkins.getSecurityRealm();
    }
}
