/*
Copyright 2019-2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import React from 'react';
import { Flex, Indicator, Box, ButtonPrimary } from 'design';

import styled from 'styled-components';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import ErrorMessage from 'teleport/components/AgentErrorMessage';
import useTeleport from 'teleport/useTeleport';

import { useResources } from './useResources';
import { ResourceCard } from './ResourceCard';
import { UnifiedResource } from 'teleport/services/agents';
import { gap } from 'design/system';

export function Resources() {
  const teleCtx = useTeleport();
  const { attempt, fetchedData, fetchMore } = useResources(teleCtx);
  const observed = React.useRef(null);

  React.useEffect(() => {
    if (observed.current) {
      const observer = new IntersectionObserver(entries => {
        console.log('INTERSECT', entries[0]);
        if (entries[0].isIntersecting) {
          fetchMore();
        }
      });
      observer.observe(observed.current);
      return () => observer.disconnect();
    }
  });

  return (
    <FeatureBox>
      <FeatureHeader alignItems="center" justifyContent="space-between">
        <FeatureHeaderTitle>Resources</FeatureHeaderTitle>
      </FeatureHeader>
      {attempt.status === 'failed' && (
        <ErrorMessage message={attempt.statusText} />
      )}
      {attempt.status === 'processing' && (
        <Box textAlign="center" m={10}>
          <Indicator />
        </Box>
      )}
      {attempt.status === 'success' && (
        <>
          <ResourcesContainer gap={2}>
            {fetchedData.agents.map((agent, i) => (
              <ResourceCard key={i} resource={agent} />
            ))}
          </ResourcesContainer>
          {fetchedData.startKey && (
            <div ref={observed}>
              <Indicator />
            </div>
          )}
        </>
      )}
    </FeatureBox>
  );
}

// TODO(bl-nero): this is almost certainly not unique.
// function agentKey(agent: UnifiedResource): string {
//   return `${agent.kind}:${agent.name}`;
// }

const ResourcesContainer = styled(Flex)`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
`;
