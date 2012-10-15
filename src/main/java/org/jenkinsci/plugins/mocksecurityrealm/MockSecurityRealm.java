package org.jenkinsci.plugins.mocksecurityrealm;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

// XXX extend SecurityRealm directly and replace login/logout links with a simple pulldown in page header

/**
 * Mock security realm with no actual security.
 */
public class MockSecurityRealm extends AbstractPasswordBasedSecurityRealm {
    
    private final String data;

    @DataBoundConstructor public MockSecurityRealm(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }

    private Map<String,Set<String>> usersAndGroups() {
        Map<String,Set<String>> r = new HashMap<String,Set<String>>();
        for (String line : data.split("\r?\n")) {
            String s = line.trim();
            if (s.isEmpty()) {
                continue;
            }
            String[] names = s.split(" +");
            r.put(names[0], new TreeSet<String>(Arrays.asList(names).subList(1, names.length)));
        }
        return r;
    }

    @Override protected UserDetails authenticate(String username, String password) throws AuthenticationException {
        UserDetails u = loadUserByUsername(username);
        if (!password.equals(username)) {
            throw new BadCredentialsException(password);
        }
        return u;
    }

    @Override public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final Set<String> groups = usersAndGroups().get(username);
        if (groups == null) {
            throw new UsernameNotFoundException(username);
        }
        List<GrantedAuthority> gs = new ArrayList<GrantedAuthority>();
        gs.add(AUTHENTICATED_AUTHORITY);
        for (String g : groups) {
            gs.add(new GrantedAuthorityImpl(g));
        }
        return new User(username, "", true, true, true, true, gs.toArray(new GrantedAuthority[gs.size()]));
    }

    @Override public GroupDetails loadGroupByGroupname(final String groupname) throws UsernameNotFoundException {
        for (Set<String> gs : usersAndGroups().values()) {
            if (gs.contains(groupname)) {
                return new GroupDetails() {
                    @Override
                    public String getName() {
                        return groupname;
                    }
                };
            }
        }
        throw new UsernameNotFoundException(groupname);
    }

    @Extension public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override public String getDisplayName() {
            return "Mock Security Realm";
        }

    }

}
