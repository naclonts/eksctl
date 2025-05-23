package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type InstanceInfo struct {
	InstanceType             string
	InstanceStorageSupported bool
	EFASupported             bool
	NvidiaGPUSupported       bool
	NvidiaGPUType            string
	NeuronSupported          bool
	NeuronDeviceType         string
	CBRSupported             bool
	CPUArch                  string
}

const ec2InstancesTemplate = `// / Generated by ` + "`" + `ec2geninfo` + "`" + `

package instance

var InstanceTypesMap = map[string]InstanceInfo{}

func init() {
	for _, instance := range InstanceTypes {
		InstanceTypesMap[instance.InstanceType] = instance
	}
}

type InstanceInfo struct { //nolint
	InstanceType             string
	InstanceStorageSupported bool
	EFASupported             bool
	NvidiaGPUSupported       bool
	NvidiaGPUType            string
	NeuronSupported          bool
	NeuronDeviceType         string
	CBRSupported             bool
	CPUArch                  string
}

var InstanceTypes = []InstanceInfo{
{{- range . }}
	{
		InstanceType:             "{{ .InstanceType }}",
		InstanceStorageSupported: {{ .InstanceStorageSupported }},
		EFASupported:             {{ .EFASupported }},
		NvidiaGPUSupported:       {{ .NvidiaGPUSupported }},
		NvidiaGPUType:            "{{ .NvidiaGPUType }}",
		NeuronSupported:          {{ .NeuronSupported }},
		NeuronDeviceType:         "{{ .NeuronDeviceType }}",
		CBRSupported:             {{ .CBRSupported }},
		CPUArch:                  "{{ .CPUArch }}",
	},
{{- end }}
}
`

func main() {
	err := updateEC2Instances()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error updating EC2 instances: %v\n", err)
		os.Exit(1)
	}
}

func updateEC2Instances() error {
	regions := []string{"us-east-1", "us-east-2", "us-west-2"}
	instances := make(map[string]InstanceInfo)

	for _, region := range regions {
		var err error
		instances, err = getEC2Instances(region, instances)
		if err != nil {
			return err
		}
	}

	tmpl, err := template.New("ec2InstancesTemplate").Parse(ec2InstancesTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create("pkg/utils/instance/instance_types.go")
	if err != nil {
		return err
	}
	defer file.Close()

	err = tmpl.Execute(file, instances)
	if err != nil {
		return err
	}

	return nil
}

func getEC2Instances(region string, instances map[string]InstanceInfo) (map[string]InstanceInfo, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	client := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstanceTypesInput{
		Filters: []types.Filter{
			{Name: aws.String("bare-metal"), Values: []string{"false"}},
		},
	}

	paginator := ec2.NewDescribeInstanceTypesPaginator(client, input)
	unsupportedRegexp, _ := regexp.Compile("^(p2).*")

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}

		for _, inst := range page.InstanceTypes {
			itype := string(inst.InstanceType)

			if unsupportedRegexp.MatchString(itype) {
				continue
			}

			efaSupported := inst.NetworkInfo != nil && inst.NetworkInfo.EfaSupported != nil && *inst.NetworkInfo.EfaSupported

			nvidiaGPUSupported := false
			nvidiaGPUType := ""
			if inst.GpuInfo != nil && len(inst.GpuInfo.Gpus) > 0 {
				nvidiaGPUSupported = *inst.GpuInfo.Gpus[0].Manufacturer == "NVIDIA"
				if nvidiaGPUSupported {
					nvidiaGPUType = *inst.GpuInfo.Gpus[0].Name
				}
			}

			neuronSupported := inst.NeuronInfo != nil
			neuronDeviceType := ""
			if neuronSupported {
				for _, acc := range inst.NeuronInfo.NeuronDevices {
					neuronDeviceType = *acc.Name
					break
				}
			}

			cbrSupported := false
			if inst.SupportedUsageClasses != nil {
				for _, usageClass := range inst.SupportedUsageClasses {
					if usageClass == types.UsageClassTypeCapacityBlock {
						cbrSupported = true
						break
					}
				}
			}

			cpuArch := "unknown"
			if inst.ProcessorInfo != nil && inst.ProcessorInfo.SupportedArchitectures != nil {
				for _, arch := range inst.ProcessorInfo.SupportedArchitectures {
					if arch == types.ArchitectureTypeArm64 || arch == types.ArchitectureTypeArm64Mac {
						cpuArch = "arm64"
					} else if arch == types.ArchitectureTypeX8664 || arch == types.ArchitectureTypeX8664Mac {
						cpuArch = "x86-64"
					}
				}
			}

			instances[itype] = InstanceInfo{
				InstanceType:             itype,
				InstanceStorageSupported: inst.InstanceStorageSupported != nil && *inst.InstanceStorageSupported,
				EFASupported:             efaSupported,
				NvidiaGPUSupported:       nvidiaGPUSupported,
				NvidiaGPUType:            nvidiaGPUType,
				NeuronSupported:          neuronSupported,
				NeuronDeviceType:         neuronDeviceType,
				CBRSupported:             cbrSupported,
				CPUArch:                  cpuArch,
			}
		}
	}

	return instances, nil
}
