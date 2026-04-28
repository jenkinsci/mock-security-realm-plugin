package org.jenkinsci.plugins.mocksecurityrealm;

import hudson.model.User;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import jenkins.model.Jenkins;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class MockSecurityRealmCascTest {

    @Rule public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

    @ConfiguredWithCode("realm-config.yml")
    @Test public void realmIsConfigured() {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        assertEquals("The users found in the 'admin' group are not the ones expected","[alice, debbie]", securityRealm.loadGroupByGroupname2("admin", true).getMembers().toString());
        assertEquals("The users found in the 'dev' group are not the ones expected","[bob]", securityRealm.loadGroupByGroupname2("dev", true).getMembers().toString());
        assertEquals("The users found in the 'qa' group are not the ones expected","[charlie, debbie]", securityRealm.loadGroupByGroupname2("qa", true).getMembers().toString());

        assertEquals("Searching for 'ADMIN' users should have returned the 'admin' users as id strategy is CASE_INSENSITIVE", "[alice, debbie]", securityRealm.loadGroupByGroupname2("ADMIN", true).getMembers().toString());
        assertEquals("Searching for 'dEv' users should have returned the 'dev' users as id strategy is CASE_INSENSITIVE","[bob]", securityRealm.loadGroupByGroupname2("dEv", true).getMembers().toString());
        assertEquals("Searching for 'qA' users should have return the 'admin' users as id strategy is CASE_INSENSITIVE", "[charlie, debbie]", securityRealm.loadGroupByGroupname2("qA", true).getMembers().toString());

        assertThat("Searching for 'Alice' should have returned the proper user as user id strategy is CASE_INSENSITIVE", securityRealm.loadUserByUsername2("alice").getUsername(), is(securityRealm.loadUserByUsername2("Alice").getUsername()));
    }

    @ConfiguredWithCode("realm-config-case-sensitive.yml")
    @Test public void realmIsConfiguredCaseSensitive() {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        assertEquals("The users in the 'ADMIN' group are not the expected as id strategy is CASE_SENSITIVE", "[Richard]", securityRealm.loadGroupByGroupname2("ADMIN", true).getMembers().toString());
    }

    @ConfiguredWithCode("realm-config-case-sensitive.yml")
    @Test(expected= UsernameNotFoundException.class) public void userNameIsCaseSensitive() {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        securityRealm.loadUserByUsername2("richard").getUsername();
    }

    @ConfiguredWithCode("realm-config-display-names.yml")
    @Test public void displayNamesAreConfigured() {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        assertThat(securityRealm.loadGroupByGroupname2("admin", false).getDisplayName(), is("Administrators"));
        assertThat(securityRealm.loadGroupByGroupname2("dev", false).getDisplayName(), is("Development"));
        assertThat(securityRealm.loadGroupByGroupname2("qa", false).getDisplayName(), is("qa"));

        securityRealm.loadUserByUsername2("alice");
        User alice = User.getById("alice", false);
        assertNotNull(alice);
        assertThat(alice.getFullName(), is("Alice Smith"));

        securityRealm.loadUserByUsername2("bob");
        User bob = User.getById("bob", false);
        assertNotNull(bob);
        assertThat(bob.getFullName(), is("Robert Jones"));
    }

    private MockSecurityRealm getMockSecurityRealm() {
        final Jenkins jenkins = Jenkins.get();
        return (MockSecurityRealm) jenkins.getSecurityRealm();
    }
}
