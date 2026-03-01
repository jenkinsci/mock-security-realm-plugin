package org.jenkinsci.plugins.mocksecurityrealm;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import jenkins.model.Jenkins;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@WithJenkinsConfiguredWithCode
class MockSecurityRealmCascTest {

    @ConfiguredWithCode("realm-config.yml")
    @Test
    void realmIsConfigured(JenkinsConfiguredWithCodeRule r) {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        assertEquals("[alice, debbie]",securityRealm.loadGroupByGroupname2("admin", true).getMembers().toString(), "The users found in the 'admin' group are not the ones expected");
        assertEquals("[bob]",securityRealm.loadGroupByGroupname2("dev", true).getMembers().toString(), "The users found in the 'dev' group are not the ones expected");
        assertEquals("[charlie, debbie]",securityRealm.loadGroupByGroupname2("qa", true).getMembers().toString(), "The users found in the 'qa' group are not the ones expected");

        assertEquals("[alice, debbie]", securityRealm.loadGroupByGroupname2("ADMIN", true).getMembers().toString(), "Searching for 'ADMIN' users should have returned the 'admin' users as id strategy is CASE_INSENSITIVE");
        assertEquals("[bob]",securityRealm.loadGroupByGroupname2("dEv", true).getMembers().toString(), "Searching for 'dEv' users should have returned the 'dev' users as id strategy is CASE_INSENSITIVE");
        assertEquals("[charlie, debbie]", securityRealm.loadGroupByGroupname2("qA", true).getMembers().toString(), "Searching for 'qA' users should have return the 'admin' users as id strategy is CASE_INSENSITIVE");

        assertThat("Searching for 'Alice' should have returned the proper user as user id strategy is CASE_INSENSITIVE", securityRealm.loadUserByUsername2("alice").getUsername(), is(securityRealm.loadUserByUsername2("Alice").getUsername()));
    }

    @ConfiguredWithCode("realm-config-case-sensitive.yml")
    @Test
    void realmIsConfiguredCaseSensitive(JenkinsConfiguredWithCodeRule r) {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        assertEquals("[Richard]", securityRealm.loadGroupByGroupname2("ADMIN", true).getMembers().toString(), "The users in the 'ADMIN' group are not the expected as id strategy is CASE_SENSITIVE");
    }

    @ConfiguredWithCode("realm-config-case-sensitive.yml")
    @Test
    void userNameIsCaseSensitive(JenkinsConfiguredWithCodeRule r) {
        final MockSecurityRealm securityRealm = getMockSecurityRealm();

        assertThrows(UsernameNotFoundException.class, () ->
            securityRealm.loadUserByUsername2("richard").getUsername());
    }

    private MockSecurityRealm getMockSecurityRealm() {
        final Jenkins jenkins = Jenkins.get();
        return (MockSecurityRealm) jenkins.getSecurityRealm();
    }
}
