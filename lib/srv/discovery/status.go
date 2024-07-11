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

package discovery

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"

	discoveryconfigv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/discoveryconfig/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/discoveryconfig"
	libevents "github.com/gravitational/teleport/lib/events"
	aws_sync "github.com/gravitational/teleport/lib/srv/discovery/fetchers/aws-sync"
	"github.com/gravitational/teleport/lib/srv/server"
)

// updateDiscoveryConfigStatus updates the DiscoveryConfig Status field with the current in-memory status.
// The status will be updated with the following matchers:
// - AWS Sync (TAG) status
// - AWS EC2 instances
func (s *Server) updateDiscoveryConfigStatus(discoveryConfigName string) {
	discoveryConfigStatus := discoveryconfig.Status{
		State:        discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_SYNCING.String(),
		LastSyncTime: s.clock.Now(),
	}

	// Merge AWS EC2 instances Status
	discoveryConfigStatus = s.awsEC2Status.mergeIntoGlobalStatus(discoveryConfigName, discoveryConfigStatus)

	// Merge AWS Sync (TAG) status
	discoveryConfigStatus = s.awsSyncStatus.mergeIntoGlobalStatus(discoveryConfigName, discoveryConfigStatus)

	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	_, err := s.AccessPoint.UpdateDiscoveryConfigStatus(ctx, discoveryConfigName, discoveryConfigStatus)
	switch {
	case trace.IsNotImplemented(err):
		s.Log.Warn("UpdateDiscoveryConfigStatus method is not implemented in Auth Server. Please upgrade it to a recent version.")
	case err != nil:
		s.Log.WithError(err).WithField("discovery_config_name", discoveryConfigName).Info("Error updating discovery config status")
	}
}

// awsSyncStatus contains all the status for aws_sync Fetchers grouped by DiscoveryConfig.
type awsSyncStatus struct {
	mu sync.RWMutex
	// awsSyncResults maps the DiscoveryConfig name to a aws_sync result.
	// Each DiscoveryConfig might have multiple `aws_sync` matchers.
	awsSyncResults map[string][]awsSyncResult
}

// awsSyncResult stores the result of the aws_sync Matchers for a given DiscoveryConfig.
type awsSyncResult struct {
	// state is the State for the DiscoveryConfigStatus.
	// Allowed values are:
	// - DISCOVERY_CONFIG_STATE_SYNCING
	// - DISCOVERY_CONFIG_STATE_ERROR
	// - DISCOVERY_CONFIG_STATE_RUNNING
	state               string
	errorMessage        *string
	lastSyncTime        time.Time
	discoveredResources uint64
}

func (d *awsSyncStatus) iterationFinished(fetchers []aws_sync.AWSSync, pushErr error, lastUpdate time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.awsSyncResults = make(map[string][]awsSyncResult)
	for _, fetcher := range fetchers {
		// Only update the status for fetchers that are from the discovery config.
		if !fetcher.IsFromDiscoveryConfig() {
			continue
		}

		count, statusErr := fetcher.Status()
		statusAndPushErr := trace.NewAggregate(statusErr, pushErr)

		fetcherResult := awsSyncResult{
			state:               discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_RUNNING.String(),
			lastSyncTime:        lastUpdate,
			discoveredResources: count,
		}

		if statusAndPushErr != nil {
			errorMessage := statusAndPushErr.Error()
			fetcherResult.errorMessage = &errorMessage
			fetcherResult.state = discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_ERROR.String()
		}

		d.awsSyncResults[fetcher.DiscoveryConfigName()] = append(d.awsSyncResults[fetcher.DiscoveryConfigName()], fetcherResult)
	}
}

func (d *awsSyncStatus) discoveryConfigs() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ret := make([]string, 0, len(d.awsSyncResults))
	for k := range d.awsSyncResults {
		ret = append(ret, k)
	}
	return ret
}

func (d *awsSyncStatus) iterationStarted(fetchers []aws_sync.AWSSync, lastUpdate time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.awsSyncResults = make(map[string][]awsSyncResult)
	for _, fetcher := range fetchers {
		// Only update the status for fetchers that are from the discovery config.
		if !fetcher.IsFromDiscoveryConfig() {
			continue
		}

		fetcherResult := awsSyncResult{
			state:        discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_SYNCING.String(),
			lastSyncTime: lastUpdate,
		}

		d.awsSyncResults[fetcher.DiscoveryConfigName()] = append(d.awsSyncResults[fetcher.DiscoveryConfigName()], fetcherResult)
	}
}

func (d *awsSyncStatus) mergeIntoGlobalStatus(discoveryConfigName string, existingStatus discoveryconfig.Status) discoveryconfig.Status {
	d.mu.RLock()
	defer d.mu.RUnlock()

	awsStatusFetchers, found := d.awsSyncResults[discoveryConfigName]
	if !found {
		return existingStatus
	}

	var statusErrorMessages []string
	if existingStatus.ErrorMessage != nil {
		statusErrorMessages = append(statusErrorMessages, *existingStatus.ErrorMessage)
	}
	for _, fetcher := range awsStatusFetchers {
		existingStatus.DiscoveredResources = existingStatus.DiscoveredResources + fetcher.discoveredResources

		// Each DiscoveryConfigStatus has a global State and Error Message, but those are produced per Fetcher.
		// We choose to keep the most informative states by favoring error states/messages.
		if fetcher.errorMessage != nil {
			statusErrorMessages = append(statusErrorMessages, *fetcher.errorMessage)
		}

		if existingStatus.State != discoveryconfigv1.DiscoveryConfigState_DISCOVERY_CONFIG_STATE_ERROR.String() {
			existingStatus.State = fetcher.state
		}

		// Keep the earliest sync time.
		if existingStatus.LastSyncTime.After(fetcher.lastSyncTime) {
			existingStatus.LastSyncTime = fetcher.lastSyncTime
		}
	}

	if len(statusErrorMessages) > 0 {
		newErrorMessage := strings.Join(statusErrorMessages, "\n")
		existingStatus.ErrorMessage = &newErrorMessage
	}

	return existingStatus
}

// awsEC2Status contains the status of the EC2 discovered resources
type awsEC2Status struct {
	mu       sync.RWMutex
	lastSync time.Time
	// discoveryConfigResources maps the DiscoveryConfig name to the resources.
	// Each status contains
	// Each DiscoveryConfig might have multiple `aws_sync` matchers.
	discoveryConfigResources map[string]map[ec2DiscoveredKey]ec2DiscoveredStatus
}

// ec2DiscoveredKey uniquely identifies an ec2 instance and an enroll mode.
type ec2DiscoveredKey struct {
	region      string
	integration string
	instanceID  string
	enrollMode  types.InstallParamEnrollMode
}

// ec2DiscoveredResourceStatus reports the result of auto-enrolling the ec2 instance into the cluster.
type ec2DiscoveredStatus struct {
	name             string
	ssmInvocationURL string
	enrollStatus     discoveryconfigv1.AWSEC2EnrollmentStatus
	enrollMessage    string
}

// startIteration resets the known status for the given discovery config.
// It also sets the initial sync
func (d *awsEC2Status) startIteration(discoveryConfigName string, lastSync time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.discoveryConfigResources == nil {
		d.discoveryConfigResources = make(map[string]map[ec2DiscoveredKey]ec2DiscoveredStatus)
	}

	d.discoveryConfigResources[discoveryConfigName] = make(map[ec2DiscoveredKey]ec2DiscoveredStatus)

	d.lastSync = lastSync
}

// upsertStatus adds or replaces the ec2
func (d *awsEC2Status) upsertStatus(discoveryConfig string, k ec2DiscoveredKey, status ec2DiscoveredStatus) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.discoveryConfigResources == nil {
		d.discoveryConfigResources = make(map[string]map[ec2DiscoveredKey]ec2DiscoveredStatus)
	}
	if d.discoveryConfigResources[discoveryConfig] == nil {
		d.discoveryConfigResources[discoveryConfig] = make(map[ec2DiscoveredKey]ec2DiscoveredStatus)
	}
	d.discoveryConfigResources[discoveryConfig][k] = status
}

func (d *awsEC2Status) mergeIntoGlobalStatus(discoveryConfig string, existingStatus discoveryconfig.Status) discoveryconfig.Status {
	d.mu.RLock()
	defer d.mu.RUnlock()

	awsStatus, found := d.discoveryConfigResources[discoveryConfig]
	if !found {
		return existingStatus
	}

	// Keep the earliest sync time.
	if existingStatus.LastSyncTime.After(d.lastSync) {
		existingStatus.LastSyncTime = d.lastSync
	}

	existingStatus.DiscoveredResources = existingStatus.DiscoveredResources + uint64(len(awsStatus))

	for resourceKey, resourceValue := range awsStatus {
		existingStatus.AWSEC2InstancesDiscovered = append(
			existingStatus.AWSEC2InstancesDiscovered,
			&discoveryconfigv1.AWSEC2InstancesDiscovered{
				Region:           resourceKey.region,
				Integration:      resourceKey.integration,
				InstanceId:       resourceKey.instanceID,
				EnrollMode:       resourceKey.enrollMode,
				EnrollStatus:     resourceValue.enrollStatus,
				EnrollMessage:    resourceValue.enrollMessage,
				Name:             resourceValue.name,
				SsmInvocationUrl: resourceValue.ssmInvocationURL,
			},
		)
	}

	return existingStatus
}

func (s *Server) ReportEC2SSMInstallationResult(ctx context.Context, result *server.SSMInstallationResult) error {
	if err := s.Emitter.EmitAuditEvent(ctx, result.SSMRunEvent); err != nil {
		return trace.Wrap(err)
	}

	if result.DiscoveryConfig == "" {
		return nil
	}

	region := result.SSMRunEvent.Region
	instanceID := result.SSMRunEvent.InstanceID
	resourceKey := ec2DiscoveredKey{
		region:      region,
		integration: result.Integration,
		enrollMode:  types.InstallParamEnrollMode_INSTALL_PARAM_ENROLL_MODE_SCRIPT,
		instanceID:  instanceID,
	}
	enrollStatus := discoveryconfigv1.AWSEC2EnrollmentStatus_AWSEC2_ENROLLMENT_STATUS_SCRIPT_SUCCESS
	if result.SSMRunEvent.Metadata.Code != libevents.SSMRunSuccessCode {
		enrollStatus = discoveryconfigv1.AWSEC2EnrollmentStatus_AWSEC2_ENROLLMENT_STATUS_SCRIPT_ERROR
	}
	resourceStatus := ec2DiscoveredStatus{
		name:             result.InstanceName,
		ssmInvocationURL: result.SSMRunEvent.InvocationURL,
		enrollStatus:     enrollStatus,
		enrollMessage:    result.SSMRunEvent.Status,
	}

	s.awsEC2Status.upsertStatus(result.DiscoveryConfig, resourceKey, resourceStatus)
	s.updateDiscoveryConfigStatus(result.DiscoveryConfig)

	return nil
}
