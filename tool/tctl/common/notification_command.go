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

package common

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/gravitational/teleport"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	notificationspb "github.com/gravitational/teleport/api/gen/proto/go/teleport/notifications/v1"
	"github.com/gravitational/teleport/api/mfa"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
)

// NotificationCommand implements the `tctl notifications` family of commands.
type NotificationCommand struct {
	ls     *kingpin.CmdClause
	rm     *kingpin.CmdClause
	create *kingpin.CmdClause

	format          string
	user            string
	roles           string
	requireAllRoles bool
	warning         bool

	title   string
	content string

	// stdout allows to switch the standard output source. Used in tests.
	stdout io.Writer
}

// Initialize allows NotificationCommand command to plug itself into the CLI parser
func (n *NotificationCommand) Initialize(app *kingpin.Application, _ *servicecfg.Config) {
	notif := app.Command("notifications", "Manage cluster notifications.")

	n.create = notif.Command("create", "Create a cluster notification.").Alias("add")
	n.create.Flag("user", "Target a specific user.").StringVar(&n.user)
	n.create.Flag("roles", "Target a specific set of roles. By default, this will target all users with any of the provided roles, use --require-all-roles to exclusively target users with all of them.").StringVar(&n.roles)
	n.create.Flag("require-all-roles", "Set whether this notification should target users who have all of the provided roles.").BoolVar(&n.requireAllRoles)
	n.create.Flag("title", "Set the notification's title.").Short('t').Required().StringVar(&n.title)
	n.create.Flag("content", "Set the notification's content.").Required().StringVar(&n.content)
	n.create.Flag("warning", "Set whether this notification is a warning notification.").BoolVar(&n.warning)

	n.ls = notif.Command("ls", "List user-created cluster notifications. This will list all user-created global notifications by default, to list user-specific notifications for a user, use the --user flag.")
	n.ls.Flag("user", "Set which user to list user-created user-specific notifications for.").StringVar(&n.user)
	n.ls.Flag("format", "Output format, 'yaml', 'json', or 'text'").Default(teleport.Text).EnumVar(&n.format, teleport.YAML, teleport.JSON, teleport.Text)

	n.rm = notif.Command("rm", "Remove a cluster notification.").Alias("remove")
	n.rm.Flag("user", "The user the notification to remove belongs to, if any.").StringVar(&n.user)
	n.rm.Arg("id", "The ID of the notification to remove.").Required().StringVar(&n.title)

	if n.stdout == nil {
		n.stdout = os.Stdout
	}
}

// TryRun takes the CLI command as an argument and executes it.
func (n *NotificationCommand) TryRun(ctx context.Context, cmd string, client *authclient.Client) (match bool, err error) {
	nc := client.NotificationServiceClient()

	switch cmd {
	case n.create.FullCommand():
		err = n.Create(ctx, client)
	case n.ls.FullCommand():
		err = n.List(ctx, nc)
	case n.rm.FullCommand():
		err = n.Remove(ctx, nc)
	default:
		return false, nil
	}
	return true, trace.Wrap(err)
}

// Create creates a new notification.
func (n *NotificationCommand) Create(ctx context.Context, client *authclient.Client) error {
	meta := &headerv1.Metadata{
		Labels: map[string]string{
			types.NotificationTitleLabel:       n.title,
			types.NotificationTextContentLabel: n.content,
		},
	}

	subKind := types.NotificationUserCreatedInformationalSubKind
	if n.warning {
		subKind = types.NotificationUserCreatedWarningSubKind
	}

	// Prompt for admin action MFA re-auth.
	mfaResponse, err := mfa.PerformAdminActionMFACeremony(ctx, client.PerformMFACeremony, true /*allowReuse*/)
	if err == nil {
		ctx = mfa.ContextWithMFAResponse(ctx, mfaResponse)
	} else if !errors.Is(err, &mfa.ErrMFANotRequired) && !errors.Is(err, &mfa.ErrMFANotSupported) {
		return trace.Wrap(err)
	}

	nc := client.NotificationServiceClient()

	if n.user != "" {
		if n.roles != "" || n.requireAllRoles {
			return trace.BadParameter("roles cannot be configured for a notification which targets a specific user")
		}

		created, err := nc.CreateUserNotification(ctx, &notificationspb.CreateUserNotificationRequest{
			Username: n.user,
			Notification: &notificationspb.Notification{
				Kind:     types.KindNotification,
				SubKind:  subKind,
				Metadata: meta,
				Spec: &notificationspb.NotificationSpec{
					Username: n.user,
				},
			},
		})

		if err != nil {
			return trail.FromGRPC(err)
		}

		fmt.Printf("\n\ncreated notification: \n%v\n", created)

		fmt.Fprintf(n.stdout, "Created notification %s for user %s\n", created.GetMetadata().GetName(), n.user)
		return nil
	}

	if n.roles != "" {
		created, err := nc.CreateGlobalNotification(ctx, &notificationspb.CreateGlobalNotificationRequest{
			GlobalNotification: &notificationspb.GlobalNotification{
				Kind: types.KindGlobalNotification,
				Spec: &notificationspb.GlobalNotificationSpec{
					Matcher: &notificationspb.GlobalNotificationSpec_ByRoles{
						ByRoles: &notificationspb.ByRoles{
							Roles: n.splitRoles(),
						},
					},
					MatchAllConditions: n.requireAllRoles,
					Notification: &notificationspb.Notification{
						Kind:     types.KindNotification,
						SubKind:  subKind,
						Metadata: meta,
						Spec:     &notificationspb.NotificationSpec{},
					},
				},
			},
		})

		if err != nil {
			return trail.FromGRPC(err)
		}

		if n.requireAllRoles {
			fmt.Fprintf(n.stdout, "Created notification %s for users with all of the following roles: %s\n", created.GetMetadata().GetName(), n.roles)
			return nil
		}

		fmt.Fprintf(n.stdout, "Created notification %s for users with one or more of the following roles: %s\n", created.GetMetadata().GetName(), n.roles)
		return nil
	}

	if n.requireAllRoles {
		return trace.BadParameter("--require-all-roles was set, but no --roles were provided")
	}

	// If roles weren't provided, default to targetting all users.
	created, err := nc.CreateGlobalNotification(ctx, &notificationspb.CreateGlobalNotificationRequest{
		GlobalNotification: &notificationspb.GlobalNotification{
			Kind: types.KindGlobalNotification,
			Spec: &notificationspb.GlobalNotificationSpec{
				Matcher: &notificationspb.GlobalNotificationSpec_All{
					All: true,
				},
				Notification: &notificationspb.Notification{
					Kind:     types.KindNotification,
					SubKind:  subKind,
					Metadata: meta,
					Spec:     &notificationspb.NotificationSpec{},
				},
			},
		},
	})

	if err != nil {
		return trail.FromGRPC(err)
	}

	fmt.Fprintf(n.stdout, "Created notification %s for all users\n", created.GetMetadata().GetName())
	return nil
}

func (n *NotificationCommand) List(ctx context.Context, client notificationspb.NotificationServiceClient) error {
	var result []*notificationspb.Notification
	var pageToken string
	for {
		var resp *notificationspb.ListNotificationsResponse
		var err error

		// If a user was specified, list user-created user-specific notifications for them, if not, default to listing user-created global notifications.
		if n.user != "" {
			resp, err = client.ListAllUserCreatedNotificationsForUser(ctx, &notificationspb.ListAllUserCreatedNotificationsForUserRequest{
				Username:  n.user,
				PageSize:  512,
				PageToken: pageToken,
			})
			if err != nil {
				return trace.Wrap(err)
			}
		} else {
			resp, err = client.ListAllUserCreatedGlobalNotifications(ctx, &notificationspb.ListAllUserCreatedGlobalNotificationsRequest{
				PageSize:  512,
				PageToken: pageToken,
			})
			if err != nil {
				return trace.Wrap(err)
			}
		}

		result = append(result, resp.Notifications...)
		pageToken = resp.GetNextPageToken()
		if pageToken == "" {
			break
		}
	}

	displayNotifications(n.format, result)
	return nil
}

func displayNotifications(format string, notifications []*notificationspb.Notification) {
	switch format {
	case teleport.Text:
		var rows [][]string
		for _, n := range notifications {
			rows = append(rows, []string{
				n.GetMetadata().GetName(),
				n.GetSpec().GetCreated().AsTime().Format(time.RFC822),
				n.GetMetadata().GetExpires().AsTime().Format(time.RFC822),
				n.GetMetadata().GetLabels()[types.NotificationTitleLabel],
			})
		}
		table := asciitable.MakeTableWithTruncatedColumn([]string{"ID", "Created", "Expires", "Title"}, rows, "Title")
		fmt.Println(table.AsBuffer().String())
	case teleport.JSON:
		utils.WriteJSONArray(os.Stdout, notifications)
	case teleport.YAML:
		utils.WriteYAML(os.Stdout, notifications)
	default:
		// Do nothing, kingpin validates the --format flag before we ever get here.
	}
}

// Remove removes a notification.
func (n *NotificationCommand) Remove(ctx context.Context, client notificationspb.NotificationServiceClient) error {
	var err error
	switch {
	case n.user != "":
		_, err = client.DeleteUserNotification(ctx, &notificationspb.DeleteUserNotificationRequest{
			Username:       n.user,
			NotificationId: n.title,
		})
	default:
		_, err = client.DeleteGlobalNotification(ctx, &notificationspb.DeleteGlobalNotificationRequest{
			NotificationId: n.title,
		})
	}

	return trail.FromGRPC(err)
}

func (n *NotificationCommand) splitRoles() []string {
	var roles []string
	for _, s := range strings.Split(n.roles, ",") {
		if s == "" {
			continue
		}
		roles = append(roles, s)
	}
	return roles
}
