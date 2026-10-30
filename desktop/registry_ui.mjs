export function emptyRegistry() {
  return { connections: [], workspaces: [], routes: [], operator_grants: [] }
}

export function cloneRegistry(value) {
  const source = value && typeof value === 'object' ? value : emptyRegistry()
  return JSON.parse(JSON.stringify(source))
}

export function csvToList(value) {
  return String(value || '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean)
}

export function routeStatus(status, routeId) {
  return (status?.routes || []).find(item => item.route_id === routeId) || null
}

const ROUTE_DESTINATION_FIELDS = new Set([
  'connection_id', 'workspace_key', 'route_type', 'project_id', 'autopilot_id', 'trigger_id', 'event'
])

export function routeDestinationFieldLocked(route, field) {
  return Boolean(route?.destination_locked && ROUTE_DESTINATION_FIELDS.has(field))
}

export function connectionForRoute(registry, route) {
  return (registry?.connections || []).find(item => item.connection_id === route?.connection_id) || null
}

export function workspacesForConnection(registry, connectionId) {
  return (registry?.workspaces || []).filter(item => item.connection_id === connectionId)
}

export function workspaceConnectionLocked(registry, workspaceKey, status) {
  return (registry?.routes || []).some(route =>
    route.workspace_key === workspaceKey && (
      route.enabled ||
      route.destination_locked ||
      Boolean(routeStatus(status, route.route_id)?.latest_delivery)
    )
  )
}

export function updateWorkspaceConnection(registry, workspaceKey, connectionId, status) {
  const workspace = (registry?.workspaces || []).find(item => item.workspace_key === workspaceKey)
  if (
    !workspace ||
    !(registry.connections || []).some(item => item.connection_id === connectionId) ||
    workspaceConnectionLocked(registry, workspaceKey, status)
  ) return false

  workspace.connection_id = connectionId
  for (const route of registry.routes || []) {
    if (route.workspace_key === workspaceKey) route.connection_id = connectionId
  }
  return true
}

export function mergeServerRouteLocks(currentRegistry, serverRegistry) {
  const next = cloneRegistry(currentRegistry)
  const server = cloneRegistry(serverRegistry)
  const serverRoutes = new Map(
    (server.routes || [])
      .filter(route => route.destination_locked)
      .map(route => [route.route_id, route])
  )
  const lockedConnectionIds = new Set()
  const lockedWorkspaceKeys = new Set()
  const currentRouteIds = new Set((next.routes || []).map(route => route.route_id))
  next.routes = (next.routes || []).map(route => {
    const persisted = serverRoutes.get(route.route_id)
    if (!persisted) return route
    lockedConnectionIds.add(persisted.connection_id)
    lockedWorkspaceKeys.add(persisted.workspace_key)
    return {
      ...route,
      connection_id: persisted.connection_id,
      workspace_key: persisted.workspace_key,
      route_type: persisted.route_type,
      project_id: persisted.project_id,
      autopilot_id: persisted.autopilot_id,
      trigger_id: persisted.trigger_id,
      event: persisted.event,
      destination_locked: true,
      tombstoned: Boolean(route.tombstoned || persisted.tombstoned),
      enabled: route.tombstoned || persisted.tombstoned ? false : route.enabled
    }
  })
  for (const [routeId, persisted] of serverRoutes) {
    if (currentRouteIds.has(routeId)) continue
    next.routes.push({ ...persisted, enabled: false, tombstoned: true })
    lockedConnectionIds.add(persisted.connection_id)
    lockedWorkspaceKeys.add(persisted.workspace_key)
  }

  const serverConnections = new Map(
    (server.connections || []).map(connection => [connection.connection_id, connection])
  )
  const currentConnectionIds = new Set((next.connections || []).map(item => item.connection_id))
  for (const connectionId of lockedConnectionIds) {
    if (!currentConnectionIds.has(connectionId) && serverConnections.has(connectionId)) {
      next.connections.push(serverConnections.get(connectionId))
    }
  }
  next.connections = (next.connections || []).map(connection => {
    if (!lockedConnectionIds.has(connection.connection_id)) return connection
    const persisted = serverConnections.get(connection.connection_id)
    return persisted
      ? { ...connection, multica_origin: persisted.multica_origin, security_mode: persisted.security_mode }
      : connection
  })

  const serverWorkspaces = new Map(
    (server.workspaces || []).map(workspace => [workspace.workspace_key, workspace])
  )
  const currentWorkspaceKeys = new Set((next.workspaces || []).map(item => item.workspace_key))
  for (const workspaceKey of lockedWorkspaceKeys) {
    if (!currentWorkspaceKeys.has(workspaceKey) && serverWorkspaces.has(workspaceKey)) {
      next.workspaces.push(serverWorkspaces.get(workspaceKey))
    }
  }
  next.workspaces = (next.workspaces || []).map(workspace => {
    if (!lockedWorkspaceKeys.has(workspace.workspace_key)) return workspace
    const persisted = serverWorkspaces.get(workspace.workspace_key)
    return persisted
      ? { ...workspace, connection_id: persisted.connection_id, workspace_id: persisted.workspace_id }
      : workspace
  })
  return next
}

export function newConnection(connectionId) {
  return {
    connection_id: connectionId,
    name: 'Новое подключение',
    multica_origin: '',
    security_mode: 'standard',
    enabled: false,
    request_timeout_seconds: 10,
    max_response_bytes: 16384,
    max_payload_bytes: 65536,
    max_requests_per_window: 5,
    window_seconds: 600,
    max_attempts_per_request: 2,
    hmac_enabled: true
  }
}

export function newWorkspace(workspaceKey, connectionId) {
  return {
    workspace_key: workspaceKey,
    connection_id: connectionId,
    name: 'Новое рабочее пространство',
    workspace_id: ''
  }
}

export function newRoute(routeId, connectionId, workspaceKey) {
  return {
    route_id: routeId,
    connection_id: connectionId,
    workspace_key: workspaceKey,
    name: 'Новый маршрут',
    route_type: 'autopilot',
    project_id: '',
    autopilot_id: '',
    trigger_id: '',
    event: 'hermes.task.dispatched',
    enabled: false,
    tombstoned: false,
    destination_locked: false,
    source_boards: [],
    allowed_profiles: [],
    allowed_assignees: [],
    operator_grant_required: false,
    result_tracking_enabled: false,
    source_platforms: [],
    allowed_user_ids: [],
    allowed_chat_ids: [],
    allow_groups: false,
    allowed_statuses: [],
    require_source_attachment: false,
    max_attachments: 0,
    max_attachment_bytes: 0,
    allowed_mime_types: [],
    allowed_extensions: [],
    watcher_enabled: false
  }
}
