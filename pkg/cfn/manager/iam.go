package manager

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/kris-nova/logger"

	api "github.com/weaveworks/eksctl/pkg/apis/eksctl.io/v1alpha5"
	"github.com/weaveworks/eksctl/pkg/cfn/builder"
	"github.com/weaveworks/eksctl/pkg/cfn/outputs"
	iamoidc "github.com/weaveworks/eksctl/pkg/iam/oidc"
)

// makeIAMServiceAccountStackName generates the name of the iamserviceaccount stack identified by its name, isolated by the cluster this StackCollection operates on and 'addon' suffix
func (c *StackCollection) makeIAMServiceAccountStackName(namespace, name string) string {
	return fmt.Sprintf("eksctl-%s-addon-iamserviceaccount-%s-%s", c.spec.Metadata.Name, namespace, name)
}

// createIAMServiceAccountTask creates the iamserviceaccount in CloudFormation
func (c *StackCollection) createIAMServiceAccountTask(ctx context.Context, errs chan error, spec *api.ClusterIAMServiceAccount, oidc *iamoidc.OpenIDConnectManager) error {
	name := c.makeIAMServiceAccountStackName(spec.Namespace, spec.Name)
	logger.Info("building iamserviceaccount stack %q", name)
	stack := builder.NewIAMRoleResourceSetForServiceAccount(spec, oidc)
	if err := stack.AddAllResources(); err != nil {
		return err
	}

	if spec.Tags == nil {
		spec.Tags = make(map[string]string)
	}
	spec.Tags[api.IAMServiceAccountNameTag] = spec.NameString()

	if err := c.CreateStack(ctx, name, stack, spec.Tags, nil, errs); err != nil {
		logger.Info("an error occurred creating the stack, to cleanup resources, run 'eksctl delete iamserviceaccount --region=%s --name=%s --namespace=%s'", c.spec.Metadata.Region, spec.Name, spec.Namespace)
		return err
	}
	return nil
}

// DescribeIAMServiceAccountStacks calls ListStacks and filters out iamserviceaccounts
func (c *StackCollection) DescribeIAMServiceAccountStacks(ctx context.Context) ([]*Stack, error) {
	stacks, err := c.ListStacks(ctx)
	if err != nil {
		return nil, err
	}

	iamServiceAccountStacks := []*Stack{}
	for _, s := range stacks {
		if s.StackStatus == types.StackStatusDeleteComplete {
			continue
		}
		if GetIAMServiceAccountName(s) != "" {
			iamServiceAccountStacks = append(iamServiceAccountStacks, s)
		}
	}
	logger.Debug("iamserviceaccounts = %v", iamServiceAccountStacks)
	return iamServiceAccountStacks, nil
}

// ListIAMServiceAccountStacks calls DescribeIAMServiceAccountStacks and returns only iamserviceaccount names
func (c *StackCollection) ListIAMServiceAccountStacks(ctx context.Context) ([]string, error) {
	stacks, err := c.DescribeIAMServiceAccountStacks(ctx)
	if err != nil {
		return nil, err
	}

	names := []string{}
	for _, s := range stacks {
		names = append(names, GetIAMServiceAccountName(s))
	}
	return names, nil
}

// GetIAMServiceAccounts calls DescribeIAMServiceAccountStacks and return native iamserviceaccounts.
// If name or namespace are provided, only service accounts matching those fields will be returned.
func (c *StackCollection) GetIAMServiceAccounts(ctx context.Context, name string, namespace string) ([]*api.ClusterIAMServiceAccount, error) {
	stacks, err := c.DescribeIAMServiceAccountStacks(ctx)
	if err != nil {
		return nil, err
	}

	results := []*api.ClusterIAMServiceAccount{}
	for _, s := range stacks {
		meta, err := api.ClusterIAMServiceAccountNameStringToClusterIAMMeta(GetIAMServiceAccountName(s))
		if err != nil {
			return nil, err
		}

		if name != "" && name != meta.Name {
			continue
		}
		if namespace != "" && namespace != meta.Namespace {
			continue
		}

		serviceAccount := &api.ClusterIAMServiceAccount{
			ClusterIAMMeta: *meta,
			Status: &api.ClusterIAMServiceAccountStatus{
				StackName: s.StackName,
			},
		}
		for _, t := range s.Tags {
			serviceAccount.Status.Tags = make(map[string]string)
			serviceAccount.Status.Tags[*t.Key] = *t.Value
		}
		for _, c := range s.Capabilities {
			serviceAccount.Status.Capabilities = make([]string, 0)
			serviceAccount.Status.Capabilities = append(serviceAccount.Status.Capabilities, string(c))
		}

		// TODO: we need to make it easier to fetch full definition of the object,
		// namely: all label, full role definition; we can do that by caching
		// the ClusterConfig time we make an update and a mechanism of validating
		// whether it is up to date;
		// otherwise we could extend this with tedious calls to each of the API,
		// but it's not very feasible and it's best ot create a general solution
		outputCollectors := outputs.NewCollectorSet(map[string]outputs.Collector{
			outputs.IAMServiceAccountRoleName: func(v string) error {
				serviceAccount.Status.RoleARN = &v
				return nil
			},
		})

		if err := outputCollectors.MustCollect(*s); err != nil {
			return nil, err
		}

		results = append(results, serviceAccount)
	}
	return results, nil
}

// GetIAMServiceAccountName will return iamserviceaccount name based on tags
func GetIAMServiceAccountName(s *Stack) string {
	for _, tag := range s.Tags {
		if *tag.Key == api.IAMServiceAccountNameTag {
			return *tag.Value
		}
	}
	return ""
}

func (c *StackCollection) GetIAMAddonsStacks(ctx context.Context) ([]*Stack, error) {
	stacks, err := c.ListStacks(ctx)
	if err != nil {
		return nil, err
	}

	iamAddonStacks := []*Stack{}
	for _, s := range stacks {
		if s.StackStatus == types.StackStatusDeleteComplete {
			continue
		}
		if GetIAMAddonName(s) != "" {
			iamAddonStacks = append(iamAddonStacks, s)
		}
	}
	return iamAddonStacks, nil
}

// GetIAMAddonName returns the addon name for stack.
func GetIAMAddonName(stack *types.Stack) string {
	for _, tag := range stack.Tags {
		if *tag.Key == api.AddonNameTag {
			return *tag.Value
		}
	}
	return ""
}
