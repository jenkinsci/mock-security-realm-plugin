package org.jenkinsci.plugins.mocksecurityrealm;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

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

    @SuppressFBWarnings(value = "SWL_SLEEP_WITH_LOCK_HELD", justification = "On purpose to introduce a delay")
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
                long effectiveDelayMillis = this.delayMillis - sqrtDelayMillis + entropy.get().nextInt(sqrtDelayMillis*2);
                try {
                    Thread.sleep(effectiveDelayMillis);
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
        Map<String,Set<String>> r = new TreeMap<>(getUserIdStrategy());
        for (String line : data.split("\r?\n")) {
            String s = line.trim();
            if (s.isEmpty()) {
                continue;
            }
            String[] names = s.split(" +");

            final TreeSet<String> groups = new TreeSet<>(getGroupIdStrategy());
            groups.addAll(Arrays.asList(names).subList(1, names.length));
            r.put(names[0], groups);
        }
        return r;
    }

    @Override protected UserDetails authenticate2(String username, String password) throws AuthenticationException {
        doDelay();
        UserDetails u = loadUserByUsername2(username);
        if (!password.equals(u.getUsername())) {
            throw new BadCredentialsException(password);
        }
        return u;
    }

    @Override public UserDetails loadUserByUsername2(String username) throws UsernameNotFoundException {
        doDelay();
        final IdStrategy idStrategy = getUserIdStrategy();
        for (Map.Entry<String, Set<String>> entry : usersAndGroups().entrySet()) {
            if (idStrategy.equals(entry.getKey(), username)) {
                List<GrantedAuthority> gs = new ArrayList<>();
                gs.add(AUTHENTICATED_AUTHORITY2);
                for (String g : entry.getValue()) {
                    gs.add(new SimpleGrantedAuthority(g));
                }
                return new User(entry.getKey(), "", true, true, true, true, gs);
            }
        }
        throw new UsernameNotFoundException(username);
    }

    @Override public GroupDetails loadGroupByGroupname2(final String groupname, boolean fetchMembers) throws UsernameNotFoundException {
        doDelay();
        final IdStrategy idStrategy = getGroupIdStrategy();
        for (Set<String> groups : usersAndGroups().values()) {
            for (final String group: groups) {
                if (idStrategy.equals(group, groupname)) {
                    return new GroupDetails() {
                        @Override
                        public String getName() {
                            return group;
                        }

                        @Override
                        public Set<String> getMembers() {
                            final IdStrategy idStrategy = getGroupIdStrategy();
                            Set<String> r = new TreeSet<>();
                            users: for (Map.Entry<String, Set<String>> entry : usersAndGroups().entrySet()) {
                                for (String groupname: entry.getValue()) {
                                    if (idStrategy.equals(group, groupname)) {
                                        r.add(entry.getKey());
                                        continue users;
                                    }
                                }
                            }
                            return r;
                        }
                    };
                }
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
