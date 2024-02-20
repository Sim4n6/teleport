/*
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

package local

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	notificationsv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/notifications/v1"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestUserNotificationCRUD tests backend operations for user-specific notification resources.
func TestUserNotificationCRUD(t *testing.T) {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	mem, err := memory.New(memory.Config{
		Context: ctx,
		Clock:   clock,
	})
	require.NoError(t, err)

	service, err := NewNotificationsService(backend.NewSanitizer(mem), clock)
	require.NoError(t, err)

	testUsername := "test-username"

	// Create a couple notifications.
	userNotification1 := newUserNotification(t, "test-notification-1")
	userNotification2 := newUserNotification(t, "test-notification-2")

	// Create notifications.
	notification, err := service.CreateUserNotification(ctx, testUsername, userNotification1)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(userNotification1, notification, protocmp.Transform()))
	notification, err = service.CreateUserNotification(ctx, testUsername, userNotification2)
	require.Empty(t, cmp.Diff(userNotification2, notification, protocmp.Transform()))
	require.NoError(t, err)

	// Test deleting a notification.
	err = service.DeleteUserNotification(ctx, testUsername, "test-notification-1")
	require.NoError(t, err)
	// Since we don't have any Get or List method for user-specific notifications specifically, we will assert that it was deleted
	// by attempting to delete it again and expecting a "not found" error.
	err = service.DeleteUserNotification(ctx, testUsername, "test-notification-1")
	require.ErrorIs(t, err, trace.NotFound(`notification "test-notification-1" doesn't exist`))

	// Test deleting a notification that doesn't exist.
	err = service.DeleteUserNotification(ctx, testUsername, "invalid-id")
	require.ErrorIs(t, err, trace.NotFound(`notification "invalid-id" doesn't exist`))

	// Test deleting all of a user's user-specific notifications.
	// Upsert userNotification1 again.
	_, err = service.CreateUserNotification(ctx, testUsername, userNotification1)
	require.NoError(t, err)
	err = service.DeleteAllUserNotificationsForUser(ctx, testUsername)
	require.NoError(t, err)
	// Verify that the notifications don't exist anymore by attempting to delete them.
	err = service.DeleteUserNotification(ctx, testUsername, "test-notification-1")
	require.ErrorIs(t, err, trace.NotFound(`notification "test-notification-1" doesn't exist`))
	err = service.DeleteUserNotification(ctx, testUsername, "test-notification-2")
	require.ErrorIs(t, err, trace.NotFound(`notification "test-notification-2" doesn't exist`))

}

// TestGlobalNotificationCRUD tests backend operations for global notification resources.
func TestGlobalNotificationCRUD(t *testing.T) {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	mem, err := memory.New(memory.Config{
		Context: ctx,
		Clock:   clock,
	})
	require.NoError(t, err)

	service, err := NewNotificationsService(backend.NewSanitizer(mem), clock)
	require.NoError(t, err)

	// Create a couple notifications.
	globalNotification1 := newGlobalNotification(t, "test-notification-1")
	globalNotification2 := newGlobalNotification(t, "test-notification-2")
	globalNotificationNoMatcher := &notificationsv1.GlobalNotification{
		Spec: &notificationsv1.GlobalNotificationSpec{
			Notification: &notificationsv1.Notification{
				SubKind: "test-subkind",
				Spec: &notificationsv1.NotificationSpec{
					Id: "notification-no-matcher",
				},
				Metadata: &headerv1.Metadata{
					Description: "Test Description",
				},
			},
		},
	}

	// Create notifications.
	notification, err := service.CreateGlobalNotification(ctx, globalNotification1)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(globalNotification1, notification, protocmp.Transform()))
	notification, err = service.CreateGlobalNotification(ctx, globalNotification2)
	require.Empty(t, cmp.Diff(globalNotification2, notification, protocmp.Transform()))
	require.NoError(t, err)
	// Expect error due to having no matcher.
	_, err = service.CreateGlobalNotification(ctx, globalNotificationNoMatcher)
	require.ErrorIs(t, err, trace.BadParameter("matcher is missing, a matcher is required for a global notification"))

	// Test deleting a notification.
	err = service.DeleteGlobalNotification(ctx, "test-notification-1")
	require.NoError(t, err)
	// Test deleting a notification that doesn't exist.
	err = service.DeleteGlobalNotification(ctx, "invalid-id")
	require.ErrorIs(t, err, trace.NotFound(`global_notification "invalid-id" doesn't exist`))
}

// TestUserNotificationStateCRUD tests backend operations for user-specific notification resources.
func TestUserNotificationStateCrud(t *testing.T) {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	mem, err := memory.New(memory.Config{
		Context: ctx,
		Clock:   clock,
	})
	require.NoError(t, err)

	service, err := NewNotificationsService(backend.NewSanitizer(mem), clock)
	require.NoError(t, err)

	testUsername := "test-username"

	userNotificationState1 := &notificationsv1.UserNotificationState{
		Spec: &notificationsv1.UserNotificationStateSpec{
			NotificationId: "test-notification-1",
		},
		Status: &notificationsv1.UserNotificationStateStatus{
			NotificationState: notificationsv1.NotificationState_NOTIFICATION_STATE_CLICKED,
		},
	}

	// Duplicate of the above but with the state set to dismissed instead of clicked.
	userNotificationState1Dismissed := &notificationsv1.UserNotificationState{
		Spec: &notificationsv1.UserNotificationStateSpec{
			NotificationId: "test-notification-1",
		},
		Status: &notificationsv1.UserNotificationStateStatus{
			NotificationState: notificationsv1.NotificationState_NOTIFICATION_STATE_DISMISSED,
		},
	}

	userNotificationState2 := &notificationsv1.UserNotificationState{
		Spec: &notificationsv1.UserNotificationStateSpec{
			NotificationId: "test-notification-2",
		},
		Status: &notificationsv1.UserNotificationStateStatus{
			NotificationState: notificationsv1.NotificationState_NOTIFICATION_STATE_CLICKED,
		},
	}

	// Initially we expect no user notification states.
	out, nextToken, err := service.ListUserNotificationStates(ctx, testUsername, 0, "")
	require.NoError(t, err)
	require.Empty(t, nextToken)
	require.Empty(t, out)

	// Upsert notification states.
	notificationState, err := service.UpsertUserNotificationState(ctx, testUsername, userNotificationState1)
	require.Empty(t, cmp.Diff(userNotificationState1, notificationState, protocmp.Transform()))
	require.NoError(t, err)
	notificationState, err = service.UpsertUserNotificationState(ctx, testUsername, userNotificationState2)
	require.Empty(t, cmp.Diff(userNotificationState2, notificationState, protocmp.Transform()))
	require.NoError(t, err)

	// Fetch a paginated list of the user's notification states.
	paginatedOut := make([]*notificationsv1.UserNotificationState, 0, 2)
	for {
		out, nextToken, err = service.ListUserNotificationStates(ctx, testUsername, 1, nextToken)
		require.NoError(t, err)

		paginatedOut = append(paginatedOut, out...)
		if nextToken == "" {
			break
		}
	}

	cmpOpts := []cmp.Option{
		protocmp.IgnoreFields(&headerv1.Metadata{}, "id", "revision"),
		protocmp.Transform(),
	}

	require.Len(t, paginatedOut, 2)
	// Verify that notification states returned are correct.
	require.Empty(t, cmp.Diff([]*notificationsv1.UserNotificationState{userNotificationState1, userNotificationState2}, paginatedOut, cmpOpts...))

	// Upsert a dismissed state with for the same notification id as userNotificationState1.
	notificationState, err = service.UpsertUserNotificationState(ctx, testUsername, userNotificationState1Dismissed)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(userNotificationState1Dismissed, notificationState, cmpOpts...))

	// Fetch the list again.
	paginatedOut = make([]*notificationsv1.UserNotificationState, 0, 2)
	for {
		out, nextToken, err = service.ListUserNotificationStates(ctx, testUsername, 1, nextToken)
		require.NoError(t, err)

		paginatedOut = append(paginatedOut, out...)
		if nextToken == "" {
			break
		}
	}

	require.Len(t, paginatedOut, 2)
	// Verify that notification id's and states are correct, userNotificationState1 should now have the dismissed state.
	require.Equal(t, userNotificationState1.Spec.NotificationId, paginatedOut[0].Spec.NotificationId)
	require.Equal(t, paginatedOut[0].Status.NotificationState, notificationsv1.NotificationState_NOTIFICATION_STATE_DISMISSED)
	require.Equal(t, userNotificationState2.Spec.NotificationId, paginatedOut[1].Spec.NotificationId)
	require.Equal(t, paginatedOut[1].Status.NotificationState, notificationsv1.NotificationState_NOTIFICATION_STATE_CLICKED)

	// Test deleting a notification state.
	err = service.DeleteUserNotificationState(ctx, testUsername, "test-notification-1")
	require.NoError(t, err)
	// Test deleting a notification state that doesn't exist.
	err = service.DeleteUserNotificationState(ctx, testUsername, "invalid-id")
	require.ErrorIs(t, err, trace.NotFound(`user_notification_state "invalid-id" doesn't exist`))

	// Fetch the list again.
	paginatedOut = make([]*notificationsv1.UserNotificationState, 0, 2)
	for {
		out, nextToken, err = service.ListUserNotificationStates(ctx, testUsername, 1, nextToken)
		require.NoError(t, err)

		paginatedOut = append(paginatedOut, out...)
		if nextToken == "" {
			break
		}
	}

	// Verify that only userNotificationState2 remains.
	require.Len(t, paginatedOut, 1)
	require.Empty(t, cmp.Diff([]*notificationsv1.UserNotificationState{userNotificationState2}, paginatedOut, cmpOpts...))

	// Upsert userNotificationState1 again.
	_, err = service.UpsertUserNotificationState(ctx, testUsername, userNotificationState1)
	require.NoError(t, err)

	// Test deleting all notification states for the user.
	err = service.DeleteAllUserNotificationStatesForUser(ctx, testUsername)
	require.NoError(t, err)
	// Verify that the user now has no notification states.
	out, nextToken, err = service.ListUserNotificationStates(ctx, testUsername, 0, "")
	require.NoError(t, err)
	require.Empty(t, nextToken)
	require.Empty(t, out)
}

// TestUserLastSeenNotificationCRUD tests backend operations for user last seen notification resources.
func TestUserLastSeenNotificationCRUD(t *testing.T) {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	mem, err := memory.New(memory.Config{
		Context: ctx,
		Clock:   clock,
	})
	require.NoError(t, err)

	service, err := NewNotificationsService(backend.NewSanitizer(mem), clock)
	require.NoError(t, err)

	testUsername := "test-username"
	testTimestamp := timestamppb.New(time.UnixMilli(1708041600000)) // February 16, 2024 12:00:00 AM UTC

	userLastSeenNotification := &notificationsv1.UserLastSeenNotification{
		Status: &notificationsv1.UserLastSeenNotificationTime{
			LastSeenTime: testTimestamp,
		},
	}

	// Initially we expect the user's last seen notification object to not exist.
	_, err = service.GetUserLastSeenNotification(ctx, testUsername)
	require.ErrorIs(t, err, trace.NotFound(`user_last_seen_notification "test-username" doesn't exist`))

	cmpOpts := []cmp.Option{
		protocmp.IgnoreFields(&headerv1.Metadata{}, "id", "revision"),
		protocmp.Transform(),
	}

	// Upsert user last seen notification.
	ulsn, err := service.UpsertUserLastSeenNotification(ctx, testUsername, userLastSeenNotification)
	require.Empty(t, cmp.Diff(userLastSeenNotification, ulsn, cmpOpts...))
	require.NoError(t, err)

	// The user's last seen notification object should now exist.
	out, err := service.GetUserLastSeenNotification(ctx, testUsername)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(userLastSeenNotification, out, cmpOpts...))

	// Test deleting a user last seen notification object.
	err = service.DeleteUserLastSeenNotification(ctx, testUsername)
	require.NoError(t, err)
	// Deleting a non-existent user last seen notification object should return an error.
	err = service.DeleteUserLastSeenNotification(ctx, "invalid-username")
	require.ErrorIs(t, err, trace.NotFound(`user_last_seen_notification "invalid-username" doesn't exist`))

	// Getting the user's last seen notification object should now fail again since we deleted it.
	_, err = service.GetUserLastSeenNotification(ctx, testUsername)
	require.ErrorIs(t, err, trace.NotFound(`user_last_seen_notification "test-username" doesn't exist`))
}

func newUserNotification(t *testing.T, notificationId string) *notificationsv1.Notification {
	t.Helper()

	notification := notificationsv1.Notification{
		SubKind: "test-subkind",
		Spec: &notificationsv1.NotificationSpec{
			Id: notificationId,
		},
		Metadata: &headerv1.Metadata{
			Labels: map[string]string{"description": notificationId},
		},
	}

	return &notification
}

func newGlobalNotification(t *testing.T, notificationId string) *notificationsv1.GlobalNotification {
	t.Helper()

	notification := notificationsv1.GlobalNotification{
		Spec: &notificationsv1.GlobalNotificationSpec{
			Matcher: &notificationsv1.GlobalNotificationSpec_All{
				All: true,
			},
			Notification: &notificationsv1.Notification{
				SubKind: "test-subkind",
				Spec: &notificationsv1.NotificationSpec{
					Id: notificationId,
				},
				Metadata: &headerv1.Metadata{
					Labels: map[string]string{"description": notificationId},
				},
			},
		},
	}

	return &notification
}
