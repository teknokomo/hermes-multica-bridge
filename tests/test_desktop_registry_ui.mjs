import assert from 'node:assert/strict'
import test from 'node:test'

import {
  cloneRegistry,
  connectionLabel,
  connectionForRoute,
  csvToList,
  emptyRegistry,
  mergeServerRouteLocks,
  newConnection,
  newRoute,
  newWorkspace,
  routeDestinationFieldLocked,
  routeStatus,
  updateWorkspaceConnection,
  workspaceConnectionLocked,
  workspacesForConnection
} from '../desktop/registry_ui.mjs'

test('registry helpers keep multi-route entities independent', () => {
  const registry = emptyRegistry()
  registry.connections.push(newConnection('018f0000-0000-7000-8000-000000000001'))
  registry.workspaces.push(
    newWorkspace('018f0000-0000-7000-8000-000000000101', registry.connections[0].connection_id),
    newWorkspace('018f0000-0000-7000-8000-000000000102', registry.connections[0].connection_id)
  )
  for (let index = 0; index < 10; index += 1) {
    registry.routes.push(newRoute(
      `018f0000-0000-7000-8000-${String(index + 1).padStart(12, '0')}`,
      registry.connections[0].connection_id,
      registry.workspaces[index % 2].workspace_key
    ))
  }

  assert.equal(registry.routes.length, 10)
  assert.equal(workspacesForConnection(registry, registry.connections[0].connection_id).length, 2)
  assert.equal(connectionForRoute(registry, registry.routes[7]).connection_id, registry.connections[0].connection_id)
})

test('connection labels use the configured security mode', () => {
  assert.equal(connectionLabel({ security_mode: 'isolated', name: 'Primary' }), 'Isolated · Primary')
  assert.equal(connectionLabel({ security_mode: 'standard', name: 'Workspace link' }), 'Standard · Workspace link')
})

test('changing an unlocked workspace connection updates all dependent routes', () => {
  const registry = emptyRegistry()
  const firstConnection = newConnection('018f0000-0000-7000-8000-000000000021')
  const secondConnection = newConnection('018f0000-0000-7000-8000-000000000022')
  const workspace = newWorkspace('018f0000-0000-7000-8000-000000000023', firstConnection.connection_id)
  registry.connections.push(firstConnection, secondConnection)
  registry.workspaces.push(workspace)
  registry.routes.push(
    newRoute('018f0000-0000-7000-8000-000000000024', firstConnection.connection_id, workspace.workspace_key),
    newRoute('018f0000-0000-7000-8000-000000000025', firstConnection.connection_id, workspace.workspace_key)
  )

  assert.equal(workspaceConnectionLocked(registry, workspace.workspace_key, null), false)
  assert.equal(updateWorkspaceConnection(registry, workspace.workspace_key, secondConnection.connection_id, null), true)
  assert.equal(workspace.connection_id, secondConnection.connection_id)
  assert.deepEqual(registry.routes.map(route => route.connection_id), [
    secondConnection.connection_id,
    secondConnection.connection_id
  ])
})

test('changing a workspace connection is blocked when a dependent route is locked', () => {
  const registry = emptyRegistry()
  const firstConnection = newConnection('018f0000-0000-7000-8000-000000000031')
  const secondConnection = newConnection('018f0000-0000-7000-8000-000000000032')
  const workspace = newWorkspace('018f0000-0000-7000-8000-000000000033', firstConnection.connection_id)
  const route = newRoute('018f0000-0000-7000-8000-000000000034', firstConnection.connection_id, workspace.workspace_key)
  route.destination_locked = true
  registry.connections.push(firstConnection, secondConnection)
  registry.workspaces.push(workspace)
  registry.routes.push(route)

  assert.equal(workspaceConnectionLocked(registry, workspace.workspace_key, null), true)
  assert.equal(updateWorkspaceConnection(registry, workspace.workspace_key, secondConnection.connection_id, null), false)
  assert.equal(workspace.connection_id, firstConnection.connection_id)
  assert.equal(route.connection_id, firstConnection.connection_id)

  route.destination_locked = false
  const status = { routes: [{ route_id: route.route_id, latest_delivery: { delivery_status: 'accepted' } }] }
  assert.equal(workspaceConnectionLocked(registry, workspace.workspace_key, status), true)
  assert.equal(updateWorkspaceConnection(registry, workspace.workspace_key, secondConnection.connection_id, status), false)
})

test('cloneRegistry and csvToList do not share mutable state', () => {
  const source = emptyRegistry()
  source.connections.push(newConnection('018f0000-0000-7000-8000-000000000001'))
  const clone = cloneRegistry(source)
  clone.connections[0].name = 'Changed'
  assert.equal(source.connections[0].name, 'Новое подключение')
  assert.deepEqual(csvToList('board-a, board-b, , board-a'), ['board-a', 'board-b', 'board-a'])
})

test('routeStatus selects readiness for the requested route only', () => {
  const status = {
    routes: [
      { route_id: 'route-a', configured: true },
      { route_id: 'route-b', configured: false }
    ]
  }
  assert.equal(routeStatus(status, 'route-b').configured, false)
  assert.equal(routeStatus(status, 'missing'), null)
})

test('locked route destination fields include the Autopilot event', () => {
  const route = { destination_locked: true }
  assert.equal(routeDestinationFieldLocked(route, 'event'), true)
  assert.equal(routeDestinationFieldLocked(route, 'trigger_id'), true)
  assert.equal(routeDestinationFieldLocked(route, 'allowed_assignees'), false)
  assert.equal(routeDestinationFieldLocked({ destination_locked: false }, 'event'), false)
})

test('mergeServerRouteLocks preserves newer draft edits while applying persisted locks', () => {
  const current = emptyRegistry()
  current.connections.push({
    connection_id: '018f0000-0000-7000-8000-000000000002',
    name: 'Draft connection name',
    multica_origin: 'https://draft.example.org',
    security_mode: 'isolated'
  })
  current.workspaces.push({
    workspace_key: '018f0000-0000-7000-8000-000000000003',
    connection_id: '018f0000-0000-7000-8000-000000000002',
    name: 'Draft workspace name',
    workspace_id: 'draft-workspace'
  })
  current.routes.push(newRoute(
    '018f0000-0000-7000-8000-000000000001',
    '018f0000-0000-7000-8000-000000000002',
    '018f0000-0000-7000-8000-000000000003'
  ))
  current.routes[0].name = 'Новое имя во время сохранения'
  const server = cloneRegistry(current)
  server.connections[0].multica_origin = 'https://persisted.example.org'
  server.connections[0].security_mode = 'standard'
  server.connections[0].name = 'Сохранённое имя connection'
  server.workspaces[0].workspace_id = 'persisted-workspace'
  server.workspaces[0].name = 'Сохранённое имя workspace'
  server.routes[0].autopilot_id = 'persisted-autopilot'
  server.routes[0].trigger_id = 'persisted-trigger'
  current.routes[0].event = 'draft-event'
  server.routes[0].event = 'persisted-event'
  server.routes[0].name = 'Сохранённое имя'
  server.routes[0].destination_locked = true

  const merged = mergeServerRouteLocks(current, server)
  assert.equal(merged.routes[0].name, 'Новое имя во время сохранения')
  assert.equal(merged.routes[0].destination_locked, true)
  assert.equal(merged.routes[0].autopilot_id, 'persisted-autopilot')
  assert.equal(merged.routes[0].trigger_id, 'persisted-trigger')
  assert.equal(merged.routes[0].event, 'persisted-event')
  assert.equal(merged.connections[0].multica_origin, 'https://persisted.example.org')
  assert.equal(merged.connections[0].security_mode, 'standard')
  assert.equal(merged.connections[0].name, 'Draft connection name')
  assert.equal(merged.workspaces[0].workspace_id, 'persisted-workspace')
  assert.equal(merged.workspaces[0].name, 'Draft workspace name')
  assert.equal(current.routes[0].destination_locked, false)
})

test('mergeServerRouteLocks preserves operator grant removals made during an in-flight save', () => {
  const current = emptyRegistry()
  const routeId = '018f0000-0000-7000-8000-000000000021'
  current.routes.push(newRoute(
    routeId,
    '018f0000-0000-7000-8000-000000000022',
    '018f0000-0000-7000-8000-000000000023'
  ))
  const server = cloneRegistry(current)
  server.routes[0].destination_locked = true
  server.operator_grants.push({ board: 'main', task_id: 'task-1', route_id: routeId })

  const merged = mergeServerRouteLocks(current, server)

  assert.deepEqual(merged.operator_grants, [])
})

test('mergeServerRouteLocks preserves a server tombstone for a route still in the draft', () => {
  const current = emptyRegistry()
  const route = newRoute(
    '018f0000-0000-7000-8000-000000000031',
    '018f0000-0000-7000-8000-000000000032',
    '018f0000-0000-7000-8000-000000000033'
  )
  current.routes.push(route)
  const server = cloneRegistry(current)
  server.routes[0].destination_locked = true
  server.routes[0].tombstoned = true
  server.routes[0].enabled = false

  const merged = mergeServerRouteLocks(current, server)

  assert.equal(merged.routes[0].tombstoned, true)
  assert.equal(merged.routes[0].enabled, false)
  assert.equal(merged.routes[0].destination_locked, true)
})

test('mergeServerRouteLocks tombstones a removed locked route and retains its grant removals', () => {
  const current = emptyRegistry()
  const server = emptyRegistry()
  const connectionId = '018f0000-0000-7000-8000-000000000012'
  const workspaceKey = '018f0000-0000-7000-8000-000000000013'
  const routeId = '018f0000-0000-7000-8000-000000000011'
  server.connections.push({
    connection_id: connectionId,
    name: 'Persisted connection',
    multica_origin: 'https://persisted.example.org',
    security_mode: 'standard',
    enabled: true
  })
  server.workspaces.push({
    workspace_key: workspaceKey,
    connection_id: connectionId,
    name: 'Persisted workspace',
    workspace_id: 'persisted-workspace'
  })
  server.routes.push({
    ...newRoute(routeId, connectionId, workspaceKey),
    autopilot_id: 'persisted-autopilot',
    trigger_id: 'persisted-trigger',
    enabled: true,
    destination_locked: true,
    operator_grant_required: true
  })
  server.operator_grants.push({ board: 'main', task_id: 'task-1', route_id: routeId })

  const merged = mergeServerRouteLocks(current, server)

  assert.deepEqual(merged.routes, [{ ...server.routes[0], enabled: false, tombstoned: true }])
  assert.deepEqual(merged.connections, server.connections)
  assert.deepEqual(merged.workspaces, server.workspaces)
  assert.deepEqual(merged.operator_grants, [])
})
