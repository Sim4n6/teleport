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

import React from 'react';
import { MemoryRouter } from 'react-router';
import { StoryObj } from '@storybook/react';

import { rest } from 'msw';

import { Context as TeleportContext, ContextProvider } from 'teleport';
import cfg from 'teleport/config';
import { clearCachedJoinTokenResult } from 'teleport/Discover/Shared/useJoinTokenSuspender';
import { PingTeleportProvider } from 'teleport/Discover/Shared/PingTeleportContext';
import { userContext } from 'teleport/Main/fixtures';
import { ResourceKind } from 'teleport/Discover/Shared';

import { UserContextProvider } from 'teleport/User';

import DownloadScript from './DownloadScript';

export default {
  title: 'Teleport/Discover/Server/DownloadScripts',
  decorators: [
    Story => {
      clearCachedJoinTokenResult([ResourceKind.Server]);
      return <Story />;
    },
  ],
};

export const Polling: StoryObj = {
  parameters: {
    msw: {
      handlers: [
        rest.get(cfg.api.nodesPath, (req, res, ctx) => {
          return res(ctx.delay('infinite'));
        }),
      ],
    },
  },
  render() {
    return (
      <Provider>
        <DownloadScript />
      </Provider>
    );
  },
};

export const LoadedWithIgs: StoryObj = {
  parameters: {
    msw: {
      handlers: [
        // Use default fetch token handler defined in mocks/handlers
        rest.get(cfg.api.nodesPath, (req, res, ctx) => {
          return res(ctx.json({ items: [{}] }));
        }),
      ],
    },
  },
  render() {
    return (
      <Provider interval={5}>
        <DownloadScript />
      </Provider>
    );
  },
};

export const PollingError: StoryObj = {
  parameters: {
    msw: {
      handlers: [
        rest.get(cfg.api.nodesPath, (req, res, ctx) => {
          return res(ctx.delay('infinite'));
        }),
      ],
    },
  },
  render() {
    return (
      <Provider timeout={50}>
        <DownloadScript />
      </Provider>
    );
  },
};

export const Processing: StoryObj = {
  parameters: {
    msw: {
      handlers: [
        rest.post(cfg.api.joinTokenPath, (req, res, ctx) => {
          return res(ctx.delay('infinite'));
        }),
      ],
    },
  },
  render() {
    return (
      <Provider interval={5}>
        <DownloadScript />
      </Provider>
    );
  },
};

export const Failed: StoryObj = {
  parameters: {
    msw: {
      handlers: [
        rest.post(cfg.api.joinTokenPath, (req, res, ctx) => {
          return res.once(ctx.status(500));
        }),
      ],
    },
  },
  render() {
    return (
      <Provider>
        <DownloadScript />
      </Provider>
    );
  },
};

const Provider = props => {
  const ctx = createTeleportContext();

  return (
    <MemoryRouter
      initialEntries={[
        { pathname: cfg.routes.discover, state: { entity: 'database' } },
      ]}
    >
      <UserContextProvider>
        <ContextProvider ctx={ctx}>
          <PingTeleportProvider
            interval={props.interval || 100000}
            resourceKind={ResourceKind.Server}
          >
            {props.children}
          </PingTeleportProvider>
        </ContextProvider>
      </UserContextProvider>
    </MemoryRouter>
  );
};

function createTeleportContext() {
  const ctx = new TeleportContext();

  ctx.isEnterprise = false;
  ctx.storeUser.setState(userContext);

  return ctx;
}
