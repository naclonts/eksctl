package az

import (
	"context"
	"fmt"
	"math/rand"
	gostrings "strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/kris-nova/logger"

	api "github.com/weaveworks/eksctl/pkg/apis/eksctl.io/v1alpha5"
	"github.com/weaveworks/eksctl/pkg/awsapi"
	"github.com/weaveworks/eksctl/pkg/utils/nodes"
	"github.com/weaveworks/eksctl/pkg/utils/strings"
)

var zoneIDsToAvoid = map[string][]string{
	api.RegionUSEast1:    {"use1-az3"},
	api.RegionUSWest1:    {"usw1-az2"},
	api.RegionCACentral1: {"cac1-az3"},
}

func GetAvailabilityZones(ctx context.Context, ec2API awsapi.EC2, region string, spec *api.ClusterConfig) ([]string, error) {
	zones, err := getZones(ctx, ec2API, region, spec)
	if err != nil {
		return nil, err
	}

	numberOfZones := len(zones)
	if numberOfZones < api.MinRequiredAvailabilityZones {
		return nil, fmt.Errorf("only %d zones discovered %v, at least %d are required", numberOfZones, zones, api.MinRequiredAvailabilityZones)
	}

	if numberOfZones < api.RecommendedAvailabilityZones {
		return zones, nil
	}

	return randomSelectionOfZones(region, zones), nil
}

func randomSelectionOfZones(region string, availableZones []string) []string {
	var zones []string
	desiredNumberOfAZs := api.RecommendedAvailabilityZones
	if region == api.RegionUSEast1 {
		desiredNumberOfAZs = api.MinRequiredAvailabilityZones
	}

	for len(zones) < desiredNumberOfAZs {
		rand := rand.New(rand.NewSource(time.Now().UnixNano()))
		for _, rn := range rand.Perm(len(availableZones)) {
			zones = append(zones, availableZones[rn])
			if len(zones) == desiredNumberOfAZs {
				break
			}
		}
	}

	return zones
}

func getZones(ctx context.Context, ec2API awsapi.EC2, region string, spec *api.ClusterConfig) ([]string, error) {
	input := &ec2.DescribeAvailabilityZonesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("region-name"),
				Values: []string{region},
			}, {
				Name:   aws.String("state"),
				Values: []string{string(ec2types.AvailabilityZoneStateAvailable)},
			}, {
				Name:   aws.String("zone-type"),
				Values: []string{string(ec2types.LocationTypeAvailabilityZone)},
			},
		},
	}

	output, err := ec2API.DescribeAvailabilityZones(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error getting availability zones for region %s: %w", region, err)
	}

	filteredZones := filterZones(region, output.AvailabilityZones)
	return FilterBasedOnAvailability(ctx, filteredZones, nodes.ToNodePools(spec), ec2API)
}

func FilterBasedOnAvailability(ctx context.Context, zones []string, np []api.NodePool, ec2API awsapi.EC2) ([]string, error) {
	uniqueInstances := nodes.CollectUniqueInstanceTypes(np)

	// Do an early exit if we don't have anything.
	if len(uniqueInstances) == 0 {
		// nothing to do
		return zones, nil
	}

	zoneToInstanceMap, err := GetInstanceTypeOfferings(ctx, ec2API, uniqueInstances, zones)
	if err != nil {
		return nil, err
	}

	// check if a randomly selected zone supports all selected instances.
	// If we find an instance that is not supported by the selected zone,
	// we do not return that zone.
	var filteredList []string
	for _, zone := range zones {
		var noSupport []string
		for _, instance := range uniqueInstances {
			if _, ok := zoneToInstanceMap[zone][instance]; !ok {
				noSupport = append(noSupport, instance)
			}
		}
		if len(noSupport) == 0 {
			filteredList = append(filteredList, zone)
		} else {
			logger.Info("skipping %s from selection because it doesn't support the following instance type(s): %s", zone, gostrings.Join(noSupport, ","))
		}
	}
	return filteredList, nil
}

func GetInstanceTypeOfferings(ctx context.Context, ec2API awsapi.EC2, instances []string, zones []string) (map[string]map[string]struct{}, error) {
	var instanceTypeOfferings []ec2types.InstanceTypeOffering
	p := ec2.NewDescribeInstanceTypeOfferingsPaginator(ec2API, &ec2.DescribeInstanceTypeOfferingsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("instance-type"),
				Values: instances,
			},
			{
				Name:   aws.String("location"),
				Values: zones,
			},
		},
		LocationType: ec2types.LocationTypeAvailabilityZone,
		MaxResults:   aws.Int32(100),
	})
	for p.HasMorePages() {
		output, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to list offerings for instance types %w", err)
		}
		instanceTypeOfferings = append(instanceTypeOfferings, output.InstanceTypeOfferings...)
	}

	// zoneToInstanceMap['us-west-1b']['t2.small']=struct{}{}
	// zoneToInstanceMap['us-west-1b']['t2.large']=struct{}{}
	zoneToInstanceMap := make(map[string]map[string]struct{})
	for _, offer := range instanceTypeOfferings {
		if _, ok := zoneToInstanceMap[aws.ToString(offer.Location)]; !ok {
			zoneToInstanceMap[aws.ToString(offer.Location)] = make(map[string]struct{})
		}
		zoneToInstanceMap[aws.ToString(offer.Location)][string(offer.InstanceType)] = struct{}{}
	}

	return zoneToInstanceMap, nil
}

func filterZones(region string, zones []ec2types.AvailabilityZone) []string {
	var filteredZones []string
	azsToAvoid := zoneIDsToAvoid[region]
	for _, z := range zones {
		if !strings.Contains(azsToAvoid, *z.ZoneId) {
			filteredZones = append(filteredZones, *z.ZoneName)
		}
	}

	return filteredZones
}
