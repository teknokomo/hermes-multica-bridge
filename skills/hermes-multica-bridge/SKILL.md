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
