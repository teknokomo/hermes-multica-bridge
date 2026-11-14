---
name: hermes-multica-bridge
description: Use the Hermes Multica Bridge for authorized Multica workspace tasks, scoped routes, and completion handoff.
---

# Hermes Multica Bridge

Use this skill when a user asks to create or manage a Multica issue through a configured Hermes workspace route. Use the bridge tools instead of the Multica CLI, direct API calls, or another integration.

## Before creating an issue

1. Call `multica_list_routes` in the current conversation and choose only a route returned for this trusted message.
2. Check its status, workspace, scope, allowed projects, assignees, `allowed_thread_ids`, and wake mode.
3. If a route is pending, disabled, absent, or outside the current source, stop and explain that an operator must configure or approve access. Never try to approve a route yourself.
4. Treat the current message as the only source of platform, user, chat, thread, and attachments. Do not infer or pass source identifiers as tool arguments.

## Project and assignment scope

- For a project route, use its single configured project.
- For a multi-project allowlist, supply the project explicitly. Do not silently choose the default project.
- For `all_workspace`, always supply `project_id`, even if only one project is currently known. This scope does not authorize projects in another workspace or imply squad-wide project membership.
- Use only an assignee returned by the route, including its exact type (`member`, `agent`, or `squad`). Do not invite people or widen an allowlist.
- The bridge binds the operation to the current thread. Never invent a thread or try another chat when the route denies this source.

## Creating and following an issue

- Use `multica_workspace_send` only after confirming the route and project scope. The bridge attaches eligible files from the current message automatically.
- A pending route cannot create issues. A missing completion wake is a warning that the final handoff is not confirmed; do not describe it as ready.
- For completion routes, `hermes-multica-notify` handles the final response. Do not send progress messages or invoke the old watcher. Wait for the normal completion result and provide one concise final response.
- Use `multica_workspace_get`, `multica_workspace_comment`, and `multica_workspace_update` only for issues proven to belong to the selected route.
- If a tool returns `route_thread_denied`, `route_project_not_allowed`, `route_not_active`, `route_grant_expired`, `source_unavailable`, or an uncertain operation result, stop that operation and report the returned condition. Do not retry by changing source or route identifiers.

## Creating a route

Use `multica_route_create` only when the user explicitly requests a new route and the current trusted message matches an operator-issued grant. The grant fixes the connection, workspace, source chat, allowed users, projects or open-workspace scope, assignees, credential anchor, and quota.

- If the tool returns `grant_required`, select only one of the returned grant IDs after the user has identified the intended workspace and scope. Never choose a grant outside that returned list.
- Choose the narrowest scope that satisfies the request. For `all_workspace`, require an explicit workspace-level grant and a default project that belongs to that workspace.
- New routes are pending unless the operator grant explicitly allows automatic approval. A pending route needs operator approval before it can be used.
- Route creation does not create a workspace, project, squad, wake subscription, or credential. Do not represent it as having done so.

Do not bypass bridge results by switching integrations or altering task source. Never expose credentials or copy a credential from another route.

## Self-service grants and topic isolation

- Grants are operator-managed policy. Never edit grants, create connections/workspaces/projects/PATs, or request broader credentials from a chat tool call.
- An empty grant thread allowlist permits creation from any otherwise-authorized topic; each created route captures the current trusted topic. Never remove that route's thread restriction. Use a distinct route name for each topic.
- A grant allowlist does not select a default assignee. When the user wants a default, pass the permitted typed `{id,type}` pair as `default_assignee` in `multica_route_create`.
- A successful create may return pending rather than active. Respect operator approval and grant quota/expiry; never approve your own pending route.
- `wake_ready` reports project coverage. Creating an intake route in another topic does not move an existing completion webhook target or create a wake subscription. Do not promise delivery to the intake topic unless the operator has confirmed that destination.
- During topic-isolation checks, inspect dynamic route IDs separately from pre-existing static routes that are legitimately visible in that topic. Do not create an issue just to test route creation.

## Agents and squads: separate CLI operations

Issue creation and updates must continue through bridge tools. Explicitly authorized agent/squad administration uses the installed Multica CLI, with an explicit approved profile and workspace:

```bash
multica --profile <service-profile> --workspace-id <workspace-id> runtime list --output json
multica --profile <approved-profile> --workspace-id <workspace-id> agent create --name <name> --runtime-id <allowed-runtime-id> --permission-mode private --max-concurrent-tasks 1 --output json
multica --profile <approved-profile> --workspace-id <workspace-id> squad create --name <name> --leader <allowed-agent-id> --output json
```

- CLI 0.8.2 uses singular `agent` and `squad`, with `--profile` as a global flag. Do not assume a configured default profile or a token environment variable.
- A member can create a squad. Agent creation also requires access to the selected runtime; workspace admin rights do not bypass runtime ownership/sharing. Confirm actual permissions rather than treating the role alone as a capability check.
- An operator profile is used only for explicitly authorized administrative operations. Never switch to it automatically after an authorization error, use it to bypass an issue route, or copy its token into a service profile.
- Trial objects belong only in the owner-approved canary workspace. Do not assign issues or start runs as part of a capability probe.
- Keep tokens out of command arguments, chat, and logs. Use existing private CLI profiles; never expose configuration secrets through `config show`.
