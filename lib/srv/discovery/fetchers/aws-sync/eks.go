/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package aws_sync

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/eks/eksiface"
	"github.com/gravitational/trace"
	"golang.org/x/sync/errgroup"

	accessgraphv1alpha "github.com/gravitational/teleport/gen/proto/go/accessgraph/v1alpha"
)

// pollAWSEKSClusters is a function that returns a function that fetches
// eks clusters and their access scope levels.
func (a *awsFetcher) pollAWSEKSClusters(ctx context.Context, result *Resources, collectErr func(error)) func() error {
	return func() error {
		output, err := a.fetchAWSSEKSClusters(ctx)
		if err != nil {
			collectErr(trace.Wrap(err, "failed to fetch eks clusters"))
		}
		result.EKSClusters = output.clusters
		result.AssociatedAccessPolicies = output.associatedPolicies
		result.AccessEntries = output.accessEntry
		return nil
	}
}

// fetchAWSEKSClustersOutput is the output of the fetchAWSSEKSClusters function.
type fetchAWSEKSClustersOutput struct {
	clusters           []*accessgraphv1alpha.AWSEKSClusterV1
	associatedPolicies []*accessgraphv1alpha.AWSEKSAssociatedAccessPolicyV1
	accessEntry        []*accessgraphv1alpha.AWSEKSClusterAccessEntryV1
}

// fetchAWSSEKSClusters fetches eks instances from all regions.
func (a *awsFetcher) fetchAWSSEKSClusters(ctx context.Context) (fetchAWSEKSClustersOutput, error) {
	var (
		output  fetchAWSEKSClustersOutput
		hostsMu sync.Mutex
		errs    []error
	)
	eG, ctx := errgroup.WithContext(ctx)
	// Set the limit to 5 to avoid too many concurrent requests.
	// This is a temporary solution until we have a better way to limit the
	// number of concurrent requests.
	eG.SetLimit(5)
	collectClusters := func(cluster *accessgraphv1alpha.AWSEKSClusterV1,
		clusterAssociatedPolicies []*accessgraphv1alpha.AWSEKSAssociatedAccessPolicyV1,
		clusterAccessEntries []*accessgraphv1alpha.AWSEKSClusterAccessEntryV1,
		err error) {
		hostsMu.Lock()
		defer hostsMu.Unlock()
		if err != nil {
			errs = append(errs, err)
		}
		if cluster != nil {
			output.clusters = append(output.clusters, cluster)
		}
		output.associatedPolicies = append(output.associatedPolicies, clusterAssociatedPolicies...)
		output.accessEntry = append(output.accessEntry, clusterAccessEntries...)
	}

	for _, region := range a.Regions {
		region := region
		eG.Go(func() error {
			eksClient, err := a.CloudClients.GetAWSEKSClient(ctx, region, a.getAWSOptions()...)
			if err != nil {
				collectClusters(nil, nil, nil, trace.Wrap(err))
				return nil
			}

			var eksClusterNames []string
			// ListClustersPagesWithContext returns a list of EKS cluster names existing in the region.
			err = eksClient.ListClustersPagesWithContext(
				ctx,
				&eks.ListClustersInput{},
				func(output *eks.ListClustersOutput, lastPage bool) bool {
					for _, cluster := range output.Clusters {
						eksClusterNames = append(eksClusterNames, aws.StringValue(cluster))
					}
					return !lastPage

				},
			)
			if err != nil {
				collectClusters(nil, nil, nil, trace.Wrap(err))
			}

			for _, cluster := range eksClusterNames {
				// DescribeClusterWithContext retrieves the cluster details.
				cluster, err := eksClient.DescribeClusterWithContext(ctx, &eks.DescribeClusterInput{
					Name: aws.String(cluster),
				},
				)
				if err != nil {
					collectClusters(nil, nil, nil, trace.Wrap(err))
					return nil
				}
				protoCluster := awsEKSClusterToProtoCluster(cluster.Cluster, region, a.AccountID)

				// if eks cluster only allows CONFIGMAP auth, skip polling of access entries and
				// associated policies.
				if cluster.Cluster != nil && cluster.Cluster.AccessConfig != nil &&
					aws.StringValue(cluster.Cluster.AccessConfig.AuthenticationMode) == eks.AuthenticationModeConfigMap {
					collectClusters(protoCluster, nil, nil, nil)
					continue
				}
				// fetchAccessEntries retries the list of configured access entries
				accessEntries, err := a.fetchAccessEntries(ctx, eksClient, protoCluster)
				if err != nil {
					collectClusters(nil, nil, nil, trace.Wrap(err))
				}

				accessEntryARNs := make([]string, 0, len(accessEntries))
				for _, accessEntry := range accessEntries {
					accessEntryARNs = append(
						accessEntryARNs,
						accessEntry.PrincipalArn,
					)
				}

				associatedPolicies, err := a.fetchAssociatedPolicies(ctx, eksClient, protoCluster, accessEntryARNs)
				if err != nil {
					collectClusters(nil, nil, nil, trace.Wrap(err))
				}
				collectClusters(protoCluster, associatedPolicies, accessEntries, nil)
			}
			return nil
		})
	}

	err := eG.Wait()
	return output, trace.NewAggregate(append(errs, err)...)
}

// awsEKSClusterToProtoCluster converts an eks.Cluster to accessgraphv1alpha.AWSEKSClusterV1
// representation.
func awsEKSClusterToProtoCluster(cluster *eks.Cluster, region, accountID string) *accessgraphv1alpha.AWSEKSClusterV1 {
	var tags []*accessgraphv1alpha.AWSTag
	for k, v := range cluster.Tags {
		tags = append(tags, &accessgraphv1alpha.AWSTag{
			Key:   k,
			Value: strPtrToWrapper(v),
		})
	}

	return &accessgraphv1alpha.AWSEKSClusterV1{
		Name:      aws.StringValue(cluster.Name),
		Arn:       aws.StringValue(cluster.Arn),
		CreatedAt: awsTimeToProtoTime(cluster.CreatedAt),
		Status:    aws.StringValue(cluster.Status),
		Region:    region,
		AccountId: accountID,
		Tags:      tags,
	}
}

// fetchAccessEntries fetches the access entries for the given cluster.
func (a *awsFetcher) fetchAccessEntries(ctx context.Context, eksClient eksiface.EKSAPI, cluster *accessgraphv1alpha.AWSEKSClusterV1) ([]*accessgraphv1alpha.AWSEKSClusterAccessEntryV1, error) {
	var accessEntries []string
	var errs []error

	err := eksClient.ListAccessEntriesPagesWithContext(
		ctx,
		&eks.ListAccessEntriesInput{
			ClusterName: aws.String(cluster.Name),
		},
		func(output *eks.ListAccessEntriesOutput, lastPage bool) bool {
			for _, accessEntry := range output.AccessEntries {
				accessEntries = append(accessEntries, aws.StringValue(accessEntry))
			}
			return !lastPage
		},
	)
	if err != nil {
		errs = append(errs, trace.Wrap(err))
		return nil, trace.NewAggregate(errs...)
	}

	var protoAccessEntries []*accessgraphv1alpha.AWSEKSClusterAccessEntryV1
	for _, accessEntry := range accessEntries {
		rsp, err := eksClient.DescribeAccessEntryWithContext(
			ctx,
			&eks.DescribeAccessEntryInput{
				PrincipalArn: aws.String(accessEntry),
				ClusterName:  aws.String(cluster.Name),
			},
		)
		if err != nil {
			errs = append(errs, trace.Wrap(err))
			continue
		}
		protoAccessEntry := awsAccessEntryToProtoAccessEntry(
			rsp.AccessEntry,
			cluster,
			a.AccountID,
		)
		protoAccessEntries = append(protoAccessEntries, protoAccessEntry)
	}
	return protoAccessEntries, trace.NewAggregate(errs...)
}

// awsAccessEntryToProtoAccessEntry converts an eks.AccessEntry to accessgraphv1alpha.AWSEKSClusterV1
func awsAccessEntryToProtoAccessEntry(accessEntry *eks.AccessEntry, cluster *accessgraphv1alpha.AWSEKSClusterV1, accountID string) *accessgraphv1alpha.AWSEKSClusterAccessEntryV1 {
	var tags []*accessgraphv1alpha.AWSTag
	for k, v := range accessEntry.Tags {
		tags = append(tags, &accessgraphv1alpha.AWSTag{
			Key:   k,
			Value: strPtrToWrapper(v),
		})
	}
	out := &accessgraphv1alpha.AWSEKSClusterAccessEntryV1{
		Cluster:          cluster,
		AccessEntryArn:   aws.StringValue(accessEntry.AccessEntryArn),
		CreatedAt:        awsTimeToProtoTime(accessEntry.CreatedAt),
		KubernetesGroups: aws.StringValueSlice(accessEntry.KubernetesGroups),
		Username:         aws.StringValue(accessEntry.Username),
		ModifiedAt:       awsTimeToProtoTime(accessEntry.ModifiedAt),
		PrincipalArn:     aws.StringValue(accessEntry.PrincipalArn),
		Type:             aws.StringValue(accessEntry.Type),
		Tags:             tags,
		AccountId:        accountID,
	}

	return out
}

// fetchAccessEntries fetches the access entries for the given cluster.
func (a *awsFetcher) fetchAssociatedPolicies(ctx context.Context, eksClient eksiface.EKSAPI, cluster *accessgraphv1alpha.AWSEKSClusterV1, arns []string) ([]*accessgraphv1alpha.AWSEKSAssociatedAccessPolicyV1, error) {
	var associatedPolicies []*accessgraphv1alpha.AWSEKSAssociatedAccessPolicyV1
	var errs []error
	for _, arn := range arns {
		err := eksClient.ListAssociatedAccessPoliciesPagesWithContext(
			ctx,
			&eks.ListAssociatedAccessPoliciesInput{
				ClusterName: aws.String(cluster.Name),
			},
			func(output *eks.ListAssociatedAccessPoliciesOutput, lastPage bool) bool {
				for _, policy := range output.AssociatedAccessPolicies {
					associatedPolicies = append(associatedPolicies,
						awsAssociatedAccessPolicy(policy, cluster, arn, a.AccountID),
					)
				}
				return !lastPage
			},
		)
		if err != nil {
			errs = append(errs, trace.Wrap(err))

		}

	}

	return associatedPolicies, trace.NewAggregate(errs...)
}

// awsAssociatedAccessPolicy converts an eks.AssociatedAccessPolicy to accessgraphv1alpha.AWSEKSAssociatedAccessPolicyV1
func awsAssociatedAccessPolicy(policy *eks.AssociatedAccessPolicy, cluster *accessgraphv1alpha.AWSEKSClusterV1, principalARN, accountID string) *accessgraphv1alpha.AWSEKSAssociatedAccessPolicyV1 {
	var accessScope *accessgraphv1alpha.AWSEKSAccessScopeV1
	if policy.AccessScope != nil {
		accessScope = &accessgraphv1alpha.AWSEKSAccessScopeV1{
			Namespaces: aws.StringValueSlice(policy.AccessScope.Namespaces),
			Type:       aws.StringValue(policy.AccessScope.Type),
		}
	}
	out := &accessgraphv1alpha.AWSEKSAssociatedAccessPolicyV1{
		Cluster:      cluster,
		AssociatedAt: awsTimeToProtoTime(policy.AssociatedAt),
		ModifiedAt:   awsTimeToProtoTime(policy.ModifiedAt),
		PrincipalArn: principalARN,
		PolicyArn:    aws.StringValue(policy.PolicyArn),
		Scope:        accessScope,
		AccountId:    accountID,
	}

	return out
}
