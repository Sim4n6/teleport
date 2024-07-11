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

import { http, HttpResponse } from 'msw';

import cfg from 'teleport/config';
import { INTERNAL_RESOURCE_ID_LABEL_KEY } from 'teleport/services/joinToken';

// handlersTeleport defines default positive (200) response values.
export const handlersTeleport = [
  http.post(cfg.api.joinTokenPath, () => {
    return HttpResponse.json({
      id: 'token-id',
      suggestedLabels: [
        { name: INTERNAL_RESOURCE_ID_LABEL_KEY, value: 'resource-id' },
      ],
    });
  }),
  http.post(cfg.api.captureUserEventPath, () => {
    return HttpResponse.json();
  }),
  http.get(cfg.api.thumbprintPath, () => {
    return HttpResponse.json('examplevaluehere');
  }),
  http.post(cfg.getIntegrationsUrl(), () => {
    return HttpResponse.json({});
  }),
];
