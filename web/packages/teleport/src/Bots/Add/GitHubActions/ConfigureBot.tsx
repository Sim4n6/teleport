/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

import React, { useState } from 'react';
import styled from 'styled-components';

import Box from 'design/Box';
import useAttempt from 'shared/hooks/useAttemptNext';
import Validation, { Validator } from 'shared/components/Validation';

import Text from 'design/Text';

import FieldInput from 'shared/components/FieldInput';

import { requiredField } from 'shared/components/Validation/rules';

import Alert from 'design/Alert';

import { botService } from 'teleport/services/bot';

import useTeleport from 'teleport/useTeleport';

import { FlowStepProps } from '../Shared/GuidedFlow';
import { FlowButtons } from '../Shared/FlowButtons';

import { LabelsInput } from '../Shared/LabelsInput';

import { useGitHubFlow } from './useGitHubFlow';

export function ConfigureBot({ nextStep, prevStep }: FlowStepProps) {
  const [missingLabels, setMissingLabels] = useState(false);
  const [alreadyExistErr, setAlreadyExistErr] = useState(false);

  const { createBotRequest, setCreateBotRequest } = useGitHubFlow();
  const { attempt, run } = useAttempt();
  const isLoading = attempt.status === 'processing';

  const ctx = useTeleport();
  const hasAccess =
    ctx.storeUser.getRoleAccess().create &&
    ctx.storeUser.getTokenAccess().create &&
    ctx.storeUser.getBotsAccess().create;

  async function handleNext(validator: Validator) {
    if (!validator.validate()) {
      return;
    }

    if (
      createBotRequest.labels.length < 1 ||
      createBotRequest.labels[0].name === ''
    ) {
      setMissingLabels(true);
      return;
    }

    // check if a bot with that name already exist
    run(async () => {
      const bot = await botService.getBot(createBotRequest.botName);
      if (bot === null) {
        nextStep();
        return;
      }
      setAlreadyExistErr(true);
    });
  }

  return (
    <Box>
      {!hasAccess && (
        <Alert kind="danger">
          <Text>
            Insufficient permissions. In order to create a bot, you need
            permissions to create roles, bots and join tokens.
          </Text>
        </Alert>
      )}
      <Text>
        GitHub Actions is a popular CI/CD platform that works as a part of the
        larger GitHub ecosystem. Teleport Machine ID allows GitHub Actions to
        securely interact with Teleport protected resources without the need for
        long-lived credentials. Through this integration, Teleport will create a
        bot-specific role that scopes its permissions in your Teleport instance
        to the necessary resources and provide inputs for your GitHub Actions
        YAML configuration.
      </Text>
      <Text my="3">
        Teleport supports secure joining on both GitHub-hosted and self-hosted
        GitHub Actions runners as well as GitHub Enterprise Server.
      </Text>

      <Text bold fontSize={4} mb="3">
        Step 1: Scope the Permissions for Your Machine User
      </Text>
      <Validation>
        {({ validator }) => (
          <>
            <Box mb="4">
              <Text>
                These first fields will enable Teleport to scope access to only
                what is needed by your GitHub Actions workflow.
              </Text>
              {missingLabels && (
                <Text mt="1" color="error.main">
                  At least one label is required
                </Text>
              )}
              <LabelsInput
                labels={createBotRequest.labels}
                setLabels={labels =>
                  setCreateBotRequest({ ...createBotRequest, labels: labels })
                }
                disableBtns={false} // TODO
              />
            </Box>
            <FormItem>
              <Text>
                SSH User that Your Machine User Can Access{' '}
                <Text
                  style={{ display: 'inline' }}
                  fontWeight="lighter"
                  fontSize="1"
                >
                  (optional)
                </Text>
              </Text>
              <FieldInput
                mb={3}
                placeholder="ex. ubuntu"
                value={createBotRequest.login}
                onChange={e =>
                  setCreateBotRequest({
                    ...createBotRequest,
                    login: e.target.value,
                  })
                }
              />
            </FormItem>

            <FormItem>
              <Text>Create a Name for Your Machine User *</Text>
              <FieldInput
                rule={requiredField('Name for Machine User is required')}
                mb={3}
                placeholder="ex. github-actions-cd"
                value={createBotRequest.botName}
                onChange={e =>
                  setCreateBotRequest({
                    ...createBotRequest,
                    botName: e.target.value,
                  })
                }
              />
            </FormItem>

            {attempt.status === 'failed' && <Alert>{attempt.statusText}</Alert>}
            {alreadyExistErr && (
              <Alert>
                A bot with this name already exist, please use a different name.
              </Alert>
            )}

            <FlowButtons
              isFirst={true}
              nextStep={() => handleNext(validator)}
              prevStep={prevStep}
              nextButton={{
                disabled: !hasAccess || isLoading,
              }}
            />
          </>
        )}
      </Validation>
    </Box>
  );
}

const FormItem = styled(Box)`
  margin-bottom: ${props => props.theme.space[4]}px;
  max-width: 500px;
`;
