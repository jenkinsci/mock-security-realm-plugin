package org.jenkinsci.plugins.mocksecurityrealm;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import jenkins.model.IdStrategy;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;

// XXX extend SecurityRealm directly and replace login/logout links with a simple pulldown in page header

/**
 * Mock security realm with no actual security.
 */
public class MockSecurityRealm extends AbstractPasswordBasedSecurityRealm {
    
    private final String data;

    private final Long delayMillis;

    private final boolean randomDelay;

    private final IdStrategy userIdStrategy;

    private final IdStrategy groupIdStrategy;

    private transient ThreadLocal<Random> entropy;

    private transient int sqrtDelayMillis;

    @DataBoundConstructor
    public MockSecurityRealm(String data, Long delayMillis, boolean randomDelay,
                                                   IdStrategy userIdStrategy, IdStrategy groupIdStrategy) {
        this.data = data;
        this.randomDelay = randomDelay;
        this.userIdStrategy = userIdStrategy == null ? IdStrategy.CASE_INSENSITIVE : userIdStrategy;
        this.groupIdStrategy = groupIdStrategy == null ? IdStrategy.CASE_INSENSITIVE : groupIdStrategy;
        this.delayMillis = delayMillis == null || delayMillis <= 0 ? null : delayMillis;
    }

    public String getData() {
        return data;
    }

    public Long getDelayMillis() {
        return delayMillis;
    }

    public boolean isRandomDelay() {
        return randomDelay;
    }

    @Override public IdStrategy getUserIdStrategy() {
        return userIdStrategy == null ? IdStrategy.CASE_INSENSITIVE : userIdStrategy;
    }

    @Override public IdStrategy getGroupIdStrategy() {
        return groupIdStrategy == null ? IdStrategy.CASE_INSENSITIVE : groupIdStrategy;
    }

    private void doDelay() {
        if (delayMillis == null) return;
        if (randomDelay) {
            synchronized (this) {
                if (entropy == null) {
                    entropy = new ThreadLocal<Random>(){
                        @Override
                        protected Random initialValue() {
                            return new Random();
                        }
                    };
                    sqrtDelayMillis = (int)Math.sqrt(delayMillis);
                }
                long delayMillis = this.delayMillis - sqrtDelayMillis + entropy.get().nextInt(sqrtDelayMillis*2);
                try {
                    Thread.sleep(delayMillis);
                } catch (InterruptedException e) {
                    // ignore
                }
            }
        } else {
            try {
                Thread.sleep(delayMillis);
            } catch (InterruptedException e) {
                // ignore
            }
        }
    }

    private Map<String,Set<String>> usersAndGroups() {
        Map<String,Set<String>> r = new TreeMap<String, Set<String>>(getUserIdStrategy());
        for (String line : data.split("\r?\n")) {
            String s = line.trim();
            if (s.isEmpty()) {
                continue;
            }
            String[] names = s.split(" +");

            final TreeSet<String> groups = new TreeSet<String>(getGroupIdStrategy());
            groups.addAll(Arrays.asList(names).subList(1, names.length));

            /**
             * Truncate the password if set
             */
            r.put(names[0].split("/")[0], groups);
        }
        return r;
    }

    /**
     * Return the users password if set. Otherwise return an empty string.
     * @param username
     * @return
     */
    private String getUserPassword(String username) {
        String password = "";
        for (String line : data.split("\r?\n")) {
            String s = line.trim();
            if (s.isEmpty()) {
                continue;
            }
            String[] names = s.split(" +");

            /**
             * Check if password is set. If not, set username as password to have compatibility with older mock impleme-
             * ntations
             */
            String[] usernamePassword = names[0].split("/");

            if (!usernamePassword[0].equals(username)) {
                continue;
            }

            if (usernamePassword.length > 1) {
                password = usernamePassword[1];
            }
            else {
                password = usernamePassword[0];
            }
        }
        return password;
    }

    @Override protected UserDetails authenticate(String username, String password) throws AuthenticationException {
        doDelay();
        UserDetails u = loadUserByUsername(username);
        if (!password.equals(u.getPassword())) {
            throw new BadCredentialsException(password);
        }
        return u;
    }

    @Override public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        doDelay();
        final Set<String> groups = usersAndGroups().get(username);
        if (groups == null) {
            throw new UsernameNotFoundException(username);
        }
        List<GrantedAuthority> gs = new ArrayList<GrantedAuthority>();
        gs.add(AUTHENTICATED_AUTHORITY);
        for (String g : groups) {
            gs.add(new GrantedAuthorityImpl(g));
        }
        return new User(username, getUserPassword(username), true, true, true, true, gs.toArray(new GrantedAuthority[gs.size()]));
    }

    @Override public GroupDetails loadGroupByGroupname(final String groupname) throws UsernameNotFoundException {
        doDelay();
        for (Set<String> gs : usersAndGroups().values()) {
            if (gs.contains(groupname)) {
                return new GroupDetails() {
                    @Override
                    public String getName() {
                        return groupname;
                    }
                    @Override public Set<String> getMembers() {
                        Set<String> r = new TreeSet<String>();
                        for (Map.Entry<String,Set<String>> entry : usersAndGroups().entrySet()) {
                            if (entry.getValue().contains(groupname)) {
                                r.add(entry.getKey());
                            }
                        }
                        return r;
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

        public IdStrategy getDefaultIdStrategy() { return IdStrategy.CASE_INSENSITIVE; }

    }

}
