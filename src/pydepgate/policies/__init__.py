"""pydepgate.policies.__init__

Policies for pydepgate. This is what processes scan profiles and enforces policies.

Unless otherwise noted, policies are applied in a manner where the more specific / granular policies take precedence over the more general ones.

The stronger policy wins, and the more specific policy will override the more general one.

In the event where you have multiple policies that could apply to the same situation, the system will prioritize the more specific policy over the more general one.

You can override this by setting [policy_override] with an integer value in the TOML configuration (or policy_override.value in JSON)

This is not expected to change or become less specific in the future. When org and group policies exist, the order is:

1. Organization-level policies
2. Group-level policies
3. User-level policies
4. System-defaults

Setting any or all of the above policies will override the default behavior if the default behavior is of lower specificity and strictness.

User policies always override default policies, if defined.

If org and group policies are defined, they will take precedence over user-level policies, even if the user-level policies are more specific.

Policies once processed and used in a scan profile will generate an AppliedPolicyResult object, which is the end result of all applicable policies being applied.

If a policy is not defined at a specific level, the system will fall back to the next level in the hierarchy. System defaults will be used if no other policies are defined.

New policies can be fetched from group and org levels via policyd.

You can use the 'inherit' parameter in the TOML file to inherit policies from a parent level or other policy file in the local directory.

For inheriting org and group policies, you would use the following syntax in the TOML file:

[inherit]
org = "pydepgatepolicy://[IP/Domain]/<orgname>/policies.toml"
group = "pydepgatepolicy://[IP/Domain]/<orgname>/<groupname>/policies.toml"

This tells pydepgate to use policyd to fetch and apply the inherited policies. This WILL FAIL if you do not have an enrolled mTLS certificate.

Policy checks against online sources are performed periodically (900 seconds unless manually refreshed, this is configurable).

"""
