import { ROUTES_AREA, SIDEBAR_NAV_AREA, host, useValue } from '@hermes/plugin-sdk'
import { useCallback, useEffect, useRef, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

import {
  clearSavedCredentialDraft,
  profileScopedGrantDraft,
  requestResultIsCurrent,
  saveResultCanReplaceDraft,
  saveResultIsCurrent
} from './profile_guard.mjs'
import {
  cloneRegistry,
  connectionLabel,
  connectionForRoute,
  csvToList,
  mergeServerRouteLocks,
  newConnection,
  newRoute,
  newWorkspace,
  routeDestinationFieldLocked,
  routeStatus,
  updateWorkspaceConnection,
  workspaceConnectionLocked,
  workspacesForConnection
} from './registry_ui.mjs'

const PLUGIN_ID = 'hermes-multica-bridge'
const panelStyle = { display: 'grid', gap: '12px', maxWidth: '1040px', padding: '16px' }
const cardStyle = {
  border: '1px solid var(--ui-stroke-secondary)',
  borderRadius: '10px',
  display: 'grid',
  gap: '10px',
  padding: '14px'
}
const inputStyle = {
  border: '1px solid var(--ui-stroke-secondary)',
  borderRadius: '7px',
  boxSizing: 'border-box',
  color: 'inherit',
  padding: '8px 10px',
  width: '100%'
}
const rowButtonsStyle = { display: 'flex', flexWrap: 'wrap', gap: '8px' }

function text(value, fallback = '—') {
  return value === null || value === undefined || value === '' ? fallback : String(value)
}

function errorText(error) {
  return error instanceof Error ? error.message : String(error)
}

function profilePath(path, profile) {
  const value = typeof profile === 'string' ? profile.trim() : ''
  if (!value) return path
  return `${path}${path.includes('?') ? '&' : '?'}profile=${encodeURIComponent(value)}`
}

function Button({ children, onClick, disabled = false }) {
  return jsx('button', {
    type: 'button',
    onClick,
    disabled,
    style: {
      border: '1px solid var(--ui-stroke-secondary)',
      borderRadius: '7px',
      color: 'inherit',
      cursor: disabled ? 'default' : 'pointer',
      opacity: disabled ? 0.6 : 1,
      padding: '7px 11px'
    },
    children
  })
}

function Row({ label, value }) {
  return jsxs('div', {
    style: { display: 'grid', gap: '10px', gridTemplateColumns: 'minmax(180px, 1fr) 2fr' },
    children: [
      jsx('span', { style: { opacity: 0.72 }, children: label }),
      jsx('span', { children: text(value) })
    ]
  })
}

function FormField({ label, value, onChange, type = 'text', disabled = false }) {
  if (type === 'checkbox') {
    return jsxs('label', {
      style: { alignItems: 'center', display: 'flex', gap: '8px' },
      children: [
        jsx('input', {
          type: 'checkbox',
          checked: Boolean(value),
          disabled,
          onChange: event => onChange(event.target.checked)
        }),
        jsx('span', { children: label })
      ]
    })
  }
  return jsxs('label', {
    style: { display: 'grid', gap: '5px' },
    children: [
      jsx('span', { children: label }),
      jsx('input', {
        style: inputStyle,
        type,
        value: value ?? '',
        disabled,
        onChange: event => onChange(event.target.value)
      })
    ]
  })
}

function SelectField({ label, value, onChange, options, disabled = false }) {
  return jsxs('label', {
    style: { display: 'grid', gap: '5px' },
    children: [
      jsx('span', { children: label }),
      jsx('select', {
        style: inputStyle,
        value: value ?? '',
        disabled,
        onChange: event => onChange(event.target.value),
        children: [
          jsx('option', { value: '', children: '— выберите —' }),
          ...options.map(option => jsx('option', {
            value: option.value,
            children: option.label
          }, option.value))
        ]
      })
    ]
  })
}

function useBridge(ctx, profile) {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [stateProfile, setStateProfile] = useState(profile)
  const requestGeneration = useRef(0)
  const activeProfile = useRef(profile)
  activeProfile.current = profile

  const refresh = useCallback(async () => {
    if (activeProfile.current !== profile) return
    const generation = ++requestGeneration.current
    setStateProfile(profile)
    setLoading(true)
    setError('')
    try {
      const next = await ctx.rest(profilePath('/status', profile))
      if (!requestResultIsCurrent(activeProfile.current, profile, requestGeneration.current, generation)) return
      setStatus(next)
    } catch (error) {
      if (requestResultIsCurrent(activeProfile.current, profile, requestGeneration.current, generation)) {
        setStatus(null)
        setError(errorText(error))
      }
    } finally {
      if (requestResultIsCurrent(activeProfile.current, profile, requestGeneration.current, generation)) {
        setLoading(false)
      }
    }
  }, [ctx, profile])

  useEffect(() => {
    requestGeneration.current += 1
    setStateProfile(profile)
    setStatus(null)
    setError('')
    setLoading(true)
    void refresh()
    return () => { requestGeneration.current += 1 }
  }, [profile, refresh])

  const currentProfile = stateProfile === profile
  return {
    status: currentProfile ? status : null,
    error: currentProfile ? error : '',
    loading: currentProfile ? loading : true,
    refresh
  }
}

function Overview({ ctx, profile }) {
  const { status, error, loading, refresh } = useBridge(ctx, profile)
  const enabledRoutes = (status?.routes || []).filter(item => item.enabled)
  return jsxs('div', {
    style: panelStyle,
    children: [
      jsx('h2', { children: 'Hermes ↔ Multica Bridge' }),
      error ? jsx('div', { role: 'alert', children: error }) : null,
      jsxs('section', {
        style: cardStyle,
        children: [
          jsx('h3', { children: 'ConnectionRegistry' }),
          jsx(Row, { label: 'Профиль Hermes', value: profile }),
          jsx(Row, { label: 'Connections', value: status?.counts?.connections ?? 0 }),
          jsx(Row, { label: 'Workspaces', value: status?.counts?.workspaces ?? 0 }),
          jsx(Row, { label: 'Routes', value: status?.counts?.routes ?? 0 }),
          jsx(Row, { label: 'Активные Routes', value: enabledRoutes.length }),
          jsx(Row, {
            label: 'Общая готовность',
            value: loading ? 'проверяется…' : (status?.configured ? 'готово' : 'требует настройки')
          }),
          jsx(Button, { onClick: () => void refresh(), children: 'Проверить снова' })
        ]
      }),
      ...(status?.routes || []).map(item => jsxs('section', {
        style: cardStyle,
        children: [
          jsx('strong', { children: item.route_id }),
          jsx(Row, {
            label: 'Состояние',
            value: item.tombstoned ? 'tombstone' : (item.enabled ? 'включён' : 'выключен')
          }),
          jsx(Row, { label: 'Режим', value: item.security_mode }),
          jsx(Row, {
            label: 'Readiness',
            value: item.configured ? 'готов' : (item.readiness_errors || []).join(', ')
          })
        ]
      }, item.route_id))
    ]
  })
}

function CredentialEditor({ ctx, profile, route, connection, routeState, refresh }) {
  const [presence, setPresence] = useState({ webhook: false, hmac: false, pat: false })
  const [values, setValues] = useState({ webhook: '', hmac: '', pat: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const requestGeneration = useRef(0)
  const saveGeneration = useRef(0)
  const activeProfile = useRef(profile)
  activeProfile.current = profile
  const credentials = ctx.credentials
  const isWorkspace = route?.route_type === 'workspace'

  const load = useCallback(async () => {
    if (!credentials || !route?.route_id) return
    const requestProfile = profile
    const generation = ++requestGeneration.current
    try {
      const [webhook, hmac, pat] = await Promise.all([
        credentials.presence(route.route_id, 'webhook', requestProfile),
        credentials.presence(route.route_id, 'hmac', requestProfile),
        credentials.presence(route.route_id, 'pat', requestProfile)
      ])
      if (!requestResultIsCurrent(activeProfile.current, requestProfile, requestGeneration.current, generation)) return
      setPresence({ webhook, hmac, pat })
      setError('')
    } catch (error) {
      if (requestResultIsCurrent(activeProfile.current, requestProfile, requestGeneration.current, generation)) {
        setError(errorText(error))
      }
    }
  }, [credentials, profile, route?.route_id])

  useEffect(() => {
    requestGeneration.current += 1
    saveGeneration.current += 1
    setPresence({ webhook: false, hmac: false, pat: false })
    setValues({ webhook: '', hmac: '', pat: '' })
    setBusy(false)
    setError('')
    void load()
    return () => {
      requestGeneration.current += 1
      saveGeneration.current += 1
    }
  }, [load, profile, route?.route_id])

  async function saveCredentials() {
    if (!credentials) return
    const saveProfile = profile
    const generation = ++saveGeneration.current
    const submittedValues = { ...values }
    const savedKinds = []
    setBusy(true)
    setError('')
    try {
      for (const kind of isWorkspace ? ['pat'] : ['webhook', 'hmac', 'pat']) {
        if (!submittedValues[kind]) continue
        const saved = await credentials.save(route.route_id, kind, submittedValues[kind], saveProfile)
        if (!saved) throw new Error('Hermes не сохранил credential. Проверьте версию Desktop/Gateway и выбранный профиль.')
        savedKinds.push(kind)
      }
      if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
        setValues(current => clearSavedCredentialDraft(current, submittedValues, savedKinds))
        await load()
        if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
          await refresh()
        }
      }
    } catch (error) {
      if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
        if (savedKinds.length) {
          setValues(current => clearSavedCredentialDraft(current, submittedValues, savedKinds))
          await load()
          if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
            try {
              await refresh()
            } catch {
              // Preserve the credential-save error; presence was already reconciled above.
            }
          }
        }
        if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
          setError(errorText(error))
        }
      }
    } finally {
      if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
        setBusy(false)
      }
    }
  }

  async function removeCredential(kind) {
    if (!credentials) return
    const saveProfile = profile
    const generation = ++saveGeneration.current
    setBusy(true)
    setError('')
    try {
      const removed = await credentials.remove(route.route_id, kind, saveProfile)
      if (!removed) throw new Error('Hermes не подтвердил удаление credential.')
      if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
        await load()
        await refresh()
      }
    } catch (error) {
      if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
        setError(errorText(error))
      }
    } finally {
      if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
        setBusy(false)
      }
    }
  }

  if (!credentials) {
    return jsx('p', {
      children: 'Текущая версия Hermes Desktop не предоставляет plugin credentials API. Обновите Hermes перед активацией Standard Route.'
    })
  }
  return jsxs('section', {
    style: cardStyle,
    children: [
      jsx('h3', { children: isWorkspace ? 'Workspace credentials выбранного Route' : 'Standard credentials выбранного Route' }),
      jsx('p', {
        style: { margin: 0, opacity: 0.72 },
        children: isWorkspace
          ? 'Multica PAT хранится в credentials текущего профиля Hermes; watcher использует отдельные systemd credentials.'
          : 'Секреты write-only: UI показывает только наличие и никогда не раскрывает сохранённое значение.'
      }),
      error ? jsx('div', { role: 'alert', children: error }) : null,
      !isWorkspace ? jsx(Row, { label: 'Webhook URL', value: presence.webhook ? 'настроен' : 'не настроен' }) : null,
      !isWorkspace ? jsx(FormField, {
        label: 'Новый webhook URL', type: 'password', value: values.webhook,
        onChange: value => setValues(current => ({ ...current, webhook: value }))
      }) : null,
      !isWorkspace ? jsx(Button, {
        onClick: () => void removeCredential('webhook'), disabled: busy || !presence.webhook,
        children: 'Удалить webhook'
      }) : null,
      !isWorkspace && connection?.hmac_enabled ? jsxs('div', {
        style: cardStyle,
        children: [
          jsx(Row, { label: 'HMAC secret', value: presence.hmac ? 'настроен' : 'не настроен' }),
          jsx(FormField, {
            label: 'Новый HMAC secret',
            type: 'password',
            value: values.hmac,
            onChange: value => setValues(current => ({ ...current, hmac: value }))
          }),
          jsx(Button, {
            onClick: () => void removeCredential('hmac'),
            disabled: busy || !presence.hmac,
            children: 'Удалить HMAC'
          })
        ]
      }) : null,
      (isWorkspace || route?.result_tracking_enabled) ? jsxs('div', {
        style: cardStyle,
        children: [
          jsx(Row, { label: 'Multica PAT', value: presence.pat ? 'настроен' : 'не настроен' }),
          jsx(FormField, {
            label: isWorkspace ? 'Новый Multica PAT для Workspace операций' : 'Новый read-only PAT',
            type: 'password',
            value: values.pat,
            onChange: value => setValues(current => ({ ...current, pat: value }))
          }),
          jsx(Button, {
            onClick: () => void removeCredential('pat'),
            disabled: busy || !presence.pat,
            children: 'Удалить PAT'
          })
        ]
      }) : null,
      jsx(Row, {
        label: 'Backend readiness',
        value: routeState?.configured ? 'готов' : (routeState?.readiness_errors || []).join(', ')
      }),
      jsx(Button, {
        onClick: () => void saveCredentials(),
        disabled: busy || !Object.values(values).some(Boolean),
        children: busy ? 'Сохранение…' : 'Сохранить/ротировать введённые секреты'
      })
    ]
  })
}

function IsolatedInstructions({ ctx, profile, routeId, refresh }) {
  const [instructions, setInstructions] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const generation = useRef(0)
  const activeProfile = useRef(profile)
  activeProfile.current = profile

  const load = useCallback(async () => {
    const requestProfile = profile
    const requestRouteId = routeId
    const requestGeneration = ++generation.current
    setInstructions(null)
    setError('')
    setLoading(true)
    try {
      const next = await ctx.rest(profilePath(
        `/isolated-instructions?route_id=${encodeURIComponent(requestRouteId)}`,
        requestProfile
      ))
      if (requestResultIsCurrent(activeProfile.current, requestProfile, generation.current, requestGeneration)) {
        setInstructions({ profile: requestProfile, routeId: requestRouteId, value: next })
        setError('')
      }
    } catch (error) {
      if (requestResultIsCurrent(activeProfile.current, requestProfile, generation.current, requestGeneration)) {
        setError(errorText(error))
      }
    } finally {
      if (requestResultIsCurrent(activeProfile.current, requestProfile, generation.current, requestGeneration)) {
        setLoading(false)
      }
    }
  }, [ctx, profile, routeId])

  useEffect(() => {
    void load()
    return () => { generation.current += 1 }
  }, [load])

  const currentInstructions = instructions?.profile === profile && instructions?.routeId === routeId
    ? instructions.value
    : null

  return jsxs('section', {
    style: cardStyle,
    children: [
      jsx('h3', { children: 'Isolated instance выбранного Route' }),
      error ? jsx('div', { role: 'alert', children: error }) : null,
      loading ? jsx('span', { children: 'Загрузка…' }) : null,
      currentInstructions ? jsxs('div', {
        style: cardStyle,
        children: [
          jsx(Row, { label: 'Instance', value: currentInstructions.instance_id }),
          jsx(Row, { label: 'Права', value: currentInstructions.requires_root ? 'выполнить от root' : 'обычный пользователь' }),
          jsx(Row, { label: 'Config', value: currentInstructions.config_path }),
          jsx(Row, { label: 'Socket', value: currentInstructions.socket_path }),
          jsx(Row, { label: 'Настройка', value: currentInstructions.setup_command }),
          jsx(Row, { label: 'Проверка', value: currentInstructions.verify_command }),
          jsx(Row, { label: 'systemd status', value: currentInstructions.systemd_status_command })
        ]
      }) : null,
      jsx(Button, {
        onClick: () => { void load(); void refresh() },
        children: 'Проверить снова'
      })
    ]
  })
}

function RegistryEditor({ ctx, profile }) {
  const { status, error, loading, refresh } = useBridge(ctx, profile)
  const [formState, setFormState] = useState(null)
  const [selectedConnection, setSelectedConnection] = useState('')
  const [selectedWorkspace, setSelectedWorkspace] = useState('')
  const [selectedRoute, setSelectedRoute] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [grantDraft, setGrantDraft] = useState(() => ({ profile, board: '', task: '' }))
  const { board: grantBoard, task: grantTask } = profileScopedGrantDraft(grantDraft, profile)
  const [listDrafts, setListDrafts] = useState({})
  const activeProfile = useRef(profile)
  const profileGeneration = useRef(0)
  const profileGenerationProfile = useRef(profile)
  const saveGeneration = useRef(0)
  const saveGenerationProfile = useRef(profile)
  const draftGeneration = useRef(0)
  activeProfile.current = profile
  if (profileGenerationProfile.current !== profile) {
    profileGenerationProfile.current = profile
    profileGeneration.current += 1
  }
  if (saveGenerationProfile.current !== profile) {
    saveGenerationProfile.current = profile
    saveGeneration.current += 1
    draftGeneration.current += 1
  }

  const registry = formState?.profile === profile ? formState.registry : null
  useEffect(() => {
    if (!status?.registry) return
    setFormState(current => current?.profile === profile
      ? current
      : { profile, registry: cloneRegistry(status.registry) })
  }, [profile, status?.registry])
  useEffect(() => {
    setSelectedConnection('')
    setSelectedWorkspace('')
    setSelectedRoute('')
    setSaveError('')
    setSaving(false)
    setListDrafts({})
    setGrantDraft({ profile, board: '', task: '' })
  }, [profile])

  function updateGrantDraft(field, value) {
    setGrantDraft(current => ({
      ...profileScopedGrantDraft(current, profile),
      [field]: value
    }))
  }

  const mutate = useCallback(mutator => {
    draftGeneration.current += 1
    setFormState(current => {
      if (current?.profile !== profile) return current
      const next = cloneRegistry(current.registry)
      mutator(next)
      return { profile, registry: next }
    })
  }, [profile])

  async function allocateId(requestProfile) {
    const result = await ctx.rest(profilePath('/new-id', requestProfile))
    return result.id
  }

  async function addConnection() {
    const requestProfile = profile
    const generation = profileGeneration.current
    try {
      const id = await allocateId(requestProfile)
      if (!requestResultIsCurrent(
        activeProfile.current,
        requestProfile,
        profileGeneration.current,
        generation
      )) return
      mutate(next => next.connections.push(newConnection(id)))
      setSelectedConnection(id)
    } catch (error) {
      if (!requestResultIsCurrent(
        activeProfile.current,
        requestProfile,
        profileGeneration.current,
        generation
      )) return
      setSaveError(errorText(error))
    }
  }

  async function addWorkspace() {
    const connectionId = selectedConnection || registry?.connections?.[0]?.connection_id
    if (!connectionId) {
      setSaveError('Сначала создайте Connection.')
      return
    }
    const requestProfile = profile
    const generation = profileGeneration.current
    try {
      const id = await allocateId(requestProfile)
      if (!requestResultIsCurrent(
        activeProfile.current,
        requestProfile,
        profileGeneration.current,
        generation
      )) return
      mutate(next => next.workspaces.push(newWorkspace(id, connectionId)))
      setSelectedWorkspace(id)
    } catch (error) {
      if (!requestResultIsCurrent(
        activeProfile.current,
        requestProfile,
        profileGeneration.current,
        generation
      )) return
      setSaveError(errorText(error))
    }
  }

  async function addRoute() {
    const connectionId = selectedConnection || registry?.connections?.[0]?.connection_id
    const selected = (registry?.workspaces || []).find(item => item.workspace_key === selectedWorkspace)
    const workspace = selected?.connection_id === connectionId
      ? selected
      : workspacesForConnection(registry, connectionId)[0]
    if (!connectionId || !workspace) {
      setSaveError('Сначала создайте Connection и Workspace.')
      return
    }
    const requestProfile = profile
    const generation = profileGeneration.current
    try {
      const id = await allocateId(requestProfile)
      if (!requestResultIsCurrent(
        activeProfile.current,
        requestProfile,
        profileGeneration.current,
        generation
      )) return
      mutate(next => next.routes.push(newRoute(id, connectionId, workspace.workspace_key)))
      setSelectedRoute(id)
    } catch (error) {
      if (!requestResultIsCurrent(
        activeProfile.current,
        requestProfile,
        profileGeneration.current,
        generation
      )) return
      setSaveError(errorText(error))
    }
  }

  async function saveRegistry() {
    if (!registry) return
    const saveProfile = profile
    const generation = ++saveGeneration.current
    const submittedDraftGeneration = draftGeneration.current
    const submittedRegistry = cloneRegistry(registry)
    setSaving(true)
    setSaveError('')
    try {
      const result = await ctx.rest(profilePath('/registry', saveProfile), {
        method: 'PUT',
        body: { registry: submittedRegistry }
      })
      if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
        if (saveResultCanReplaceDraft(
          activeProfile.current,
          saveProfile,
          saveGeneration.current,
          generation,
          draftGeneration.current,
          submittedDraftGeneration
        )) {
          setFormState({ profile: saveProfile, registry: cloneRegistry(result.registry) })
        } else {
          setFormState(current => current?.profile === saveProfile
            ? { profile: saveProfile, registry: mergeServerRouteLocks(current.registry, result.registry) }
            : current)
        }
        await refresh()
      }
    } catch (error) {
      if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
        setSaveError(errorText(error))
      }
    } finally {
      if (saveResultIsCurrent(activeProfile.current, saveProfile, saveGeneration.current, generation)) {
        setSaving(false)
      }
    }
  }

  if (loading && !registry) return jsx('div', { style: panelStyle, children: 'Загрузка ConnectionRegistry…' })
  if (!registry) return jsx('div', { style: panelStyle, children: error || 'Registry недоступен.' })

  const connection = registry.connections.find(item => item.connection_id === selectedConnection) || null
  const workspace = registry.workspaces.find(item => item.workspace_key === selectedWorkspace) || null
  const workspaceConnectionIsLocked = workspace
    ? workspaceConnectionLocked(registry, workspace.workspace_key, status)
    : true
  const route = registry.routes.find(item => item.route_id === selectedRoute) || null
  const selectedRouteConnection = connectionForRoute(registry, route)
  const selectedRouteStatus = route ? routeStatus(status, route.route_id) : null
  const routeWorkspaces = route ? workspacesForConnection(registry, route.connection_id) : []

  function updateConnection(key, value) {
    mutate(next => {
      const item = next.connections.find(row => row.connection_id === selectedConnection)
      if (item) item[key] = value
    })
  }

  function updateWorkspace(key, value) {
    mutate(next => {
      const item = next.workspaces.find(row => row.workspace_key === selectedWorkspace)
      if (!item) return
      if (key === 'connection_id') {
        updateWorkspaceConnection(next, item.workspace_key, value, status)
        return
      }
      item[key] = value
    })
  }

  function updateRoute(key, value) {
    mutate(next => {
      const item = next.routes.find(row => row.route_id === selectedRoute)
      if (!item) return
      if (routeDestinationFieldLocked(item, key)) return
      if (key === 'route_type') {
        item.route_type = value
        if (value === 'workspace') {
          Object.assign(item, {
            autopilot_id: '', trigger_id: '', event: 'hermes.task.dispatched',
            source_boards: [], allowed_profiles: [], operator_grant_required: false,
            result_tracking_enabled: false
          })
        } else {
          Object.assign(item, {
            project_id: '', source_platforms: [], allowed_user_ids: [], allowed_chat_ids: [],
            allow_groups: false, allowed_statuses: [], require_source_attachment: false,
            max_attachments: 0, max_attachment_bytes: 0, allowed_mime_types: [],
            allowed_extensions: [], watcher_enabled: false
          })
        }
        return
      }
      if (['max_attachments', 'max_attachment_bytes'].includes(key)) {
        const parsed = Number.parseInt(value, 10)
        item[key] = Number.isFinite(parsed) ? parsed : 0
        return
      }
      item[key] = value
      if (key === 'connection_id') {
        item.workspace_key = workspacesForConnection(next, value)[0]?.workspace_key || ''
      }
      if (key === 'tombstoned' && value) item.enabled = false
    })
  }

  function routeListDraft(key) {
    if (!route) return ''
    const draftKey = `${route.route_id}:${key}`
    return Object.prototype.hasOwnProperty.call(listDrafts, draftKey)
      ? listDrafts[draftKey]
      : (route[key] || []).join(', ')
  }

  function updateRouteList(key, value) {
    if (!route) return
    const draftKey = `${route.route_id}:${key}`
    setListDrafts(current => ({ ...current, [draftKey]: value }))
    updateRoute(key, csvToList(value))
  }

  function removeRoute() {
    if (!route) return
    const used = route.destination_locked || Boolean(selectedRouteStatus?.latest_delivery)
    mutate(next => {
      const item = next.routes.find(row => row.route_id === route.route_id)
      if (used && item) {
        item.enabled = false
        item.tombstoned = true
        return
      }
      next.routes = next.routes.filter(row => row.route_id !== route.route_id)
      next.operator_grants = next.operator_grants.filter(grant => grant.route_id !== route.route_id)
    })
    if (!used) setSelectedRoute('')
  }

  function addGrant() {
    if (!selectedRoute || !grantBoard.trim() || !grantTask.trim()) return
    mutate(next => next.operator_grants.push({
      board: grantBoard.trim(),
      task_id: grantTask.trim(),
      route_id: selectedRoute
    }))
    setGrantDraft({ profile, board: '', task: '' })
  }

  return jsxs('div', {
    style: panelStyle,
    children: [
      jsx('h2', { children: 'ConnectionRegistry' }),
      (error || saveError) ? jsx('div', { role: 'alert', children: error || saveError }) : null,
      jsxs('div', {
        style: rowButtonsStyle,
        children: [
          jsx(Button, {
            onClick: () => void saveRegistry(),
            disabled: saving,
            children: saving ? 'Сохранение…' : 'Сохранить registry'
          }),
          jsx(Button, { onClick: () => void refresh(), disabled: saving, children: 'Перечитать readiness' })
        ]
      }),

      jsxs('section', {
        style: cardStyle,
        children: [
          jsx('h3', { children: '1. Connections' }),
          jsxs('div', {
            style: rowButtonsStyle,
            children: [
              ...registry.connections.map(item => jsx(Button, {
                onClick: () => setSelectedConnection(item.connection_id),
                disabled: item.connection_id === selectedConnection,
                children: connectionLabel(item)
              }, item.connection_id)),
              jsx(Button, { onClick: () => void addConnection(), children: '+ Connection' })
            ]
          }),
          connection ? jsxs('div', {
            style: cardStyle,
            children: [
              jsx(Row, { label: 'Connection ID', value: connection.connection_id }),
              jsx(FormField, { label: 'Название', value: connection.name, onChange: value => updateConnection('name', value) }),
              jsx(FormField, { label: 'Multica HTTPS origin', value: connection.multica_origin, onChange: value => updateConnection('multica_origin', value) }),
              jsx(SelectField, {
                label: 'Режим безопасности',
                value: connection.security_mode,
                onChange: value => updateConnection('security_mode', value),
                options: [
                  { value: 'standard', label: 'Standard' },
                  { value: 'isolated', label: 'Isolated' }
                ]
              }),
              jsx(FormField, { label: 'Connection включён', type: 'checkbox', value: connection.enabled, onChange: value => updateConnection('enabled', value) }),
              jsx(FormField, { label: 'HMAC включён', type: 'checkbox', value: connection.hmac_enabled, onChange: value => updateConnection('hmac_enabled', value) }),
              jsx(FormField, { label: 'Request timeout, сек.', type: 'number', value: connection.request_timeout_seconds, onChange: value => updateConnection('request_timeout_seconds', Number(value)) }),
              jsx(FormField, { label: 'Rate limit: запросов', type: 'number', value: connection.max_requests_per_window, onChange: value => updateConnection('max_requests_per_window', Number(value)) }),
              jsx(FormField, { label: 'Rate limit: окно, сек.', type: 'number', value: connection.window_seconds, onChange: value => updateConnection('window_seconds', Number(value)) })
            ]
          }) : null
        ]
      }),

      jsxs('section', {
        style: cardStyle,
        children: [
          jsx('h3', { children: '2. Workspaces' }),
          jsxs('div', {
            style: rowButtonsStyle,
            children: [
              ...registry.workspaces.map(item => jsx(Button, {
                onClick: () => {
                  setSelectedWorkspace(item.workspace_key)
                  setSelectedConnection(item.connection_id)
                },
                disabled: item.workspace_key === selectedWorkspace,
                children: item.name
              }, item.workspace_key)),
              jsx(Button, { onClick: () => void addWorkspace(), children: '+ Workspace' })
            ]
          }),
          workspace ? jsxs('div', {
            style: cardStyle,
            children: [
              jsx(Row, { label: 'Workspace key', value: workspace.workspace_key }),
              jsx(SelectField, {
                label: workspaceConnectionIsLocked
                  ? 'Connection (зафиксирован связанным Route)'
                  : 'Connection',
                value: workspace.connection_id,
                disabled: workspaceConnectionIsLocked,
                onChange: value => updateWorkspace('connection_id', value),
                options: registry.connections.map(item => ({ value: item.connection_id, label: item.name }))
              }),
              jsx(FormField, { label: 'Название', value: workspace.name, onChange: value => updateWorkspace('name', value) }),
              jsx(FormField, { label: 'External Workspace ID', value: workspace.workspace_id, onChange: value => updateWorkspace('workspace_id', value) })
            ]
          }) : null
        ]
      }),

      jsxs('section', {
        style: cardStyle,
        children: [
          jsx('h3', { children: '3. Routes' }),
          jsxs('div', {
            style: rowButtonsStyle,
            children: [
              ...registry.routes.map(item => jsx(Button, {
                onClick: () => {
                  setSelectedRoute(item.route_id)
                  setSelectedConnection(item.connection_id)
                  setSelectedWorkspace(item.workspace_key)
                },
                disabled: item.route_id === selectedRoute,
                children: item.name
              }, item.route_id)),
              jsx(Button, { onClick: () => void addRoute(), children: '+ Route' })
            ]
          }),
          route ? jsxs('div', {
            style: cardStyle,
            children: [
              jsx(Row, { label: 'Route ID', value: route.route_id }),
              jsx(Row, { label: 'Destination locked', value: route.destination_locked ? 'да' : 'нет' }),
              jsx(FormField, { label: 'Название', value: route.name, onChange: value => updateRoute('name', value) }),
              jsx(SelectField, {
                label: 'Connection',
                value: route.connection_id,
                disabled: routeDestinationFieldLocked(route, 'connection_id'),
                onChange: value => updateRoute('connection_id', value),
                options: registry.connections.map(item => ({ value: item.connection_id, label: item.name }))
              }),
              jsx(SelectField, {
                label: 'Workspace',
                value: route.workspace_key,
                disabled: routeDestinationFieldLocked(route, 'workspace_key'),
                onChange: value => updateRoute('workspace_key', value),
                options: routeWorkspaces.map(item => ({ value: item.workspace_key, label: item.name }))
              }),
              jsx(SelectField, {
                label: 'Тип маршрута', value: route.route_type || 'autopilot',
                disabled: routeDestinationFieldLocked(route, 'route_type'),
                onChange: value => updateRoute('route_type', value),
                options: [
                  { value: 'autopilot', label: 'Autopilot — задача Kanban' },
                  { value: 'workspace', label: 'Workspace — задача из чата' }
                ]
              }),
              route.route_type === 'workspace' ? jsxs('div', {
                style: cardStyle,
                children: [
                  jsx(FormField, { label: 'Project ID', value: route.project_id, disabled: routeDestinationFieldLocked(route, 'project_id'), onChange: value => updateRoute('project_id', value) }),
                  jsx(FormField, { label: 'Входящие платформы (max, telegram)', value: routeListDraft('source_platforms'), onChange: value => updateRouteList('source_platforms', value) }),
                  jsx(FormField, { label: 'Разрешённые user ID', value: routeListDraft('allowed_user_ids'), onChange: value => updateRouteList('allowed_user_ids', value) }),
                  jsx(FormField, { label: 'Разрешённые chat ID', value: routeListDraft('allowed_chat_ids'), onChange: value => updateRouteList('allowed_chat_ids', value) }),
                  jsx(FormField, { label: 'Разрешить группы', type: 'checkbox', value: route.allow_groups, onChange: value => updateRoute('allow_groups', value) }),
                  jsx(FormField, { label: 'Разрешённые исполнители', value: routeListDraft('allowed_assignees'), onChange: value => updateRouteList('allowed_assignees', value) }),
                  jsx(FormField, { label: 'Разрешённые статусы', value: routeListDraft('allowed_statuses'), onChange: value => updateRouteList('allowed_statuses', value) }),
                  jsx(FormField, { label: 'Требовать вложение источника', type: 'checkbox', value: route.require_source_attachment, onChange: value => updateRoute('require_source_attachment', value) }),
                  jsx(FormField, { label: 'Максимум вложений', type: 'number', value: route.max_attachments, onChange: value => updateRoute('max_attachments', value) }),
                  jsx(FormField, { label: 'Общий лимит вложений, байт', type: 'number', value: route.max_attachment_bytes, onChange: value => updateRoute('max_attachment_bytes', value) }),
                  jsx(FormField, { label: 'Разрешённые MIME-типы', value: routeListDraft('allowed_mime_types'), onChange: value => updateRouteList('allowed_mime_types', value) }),
                  jsx(FormField, { label: 'Разрешённые расширения', value: routeListDraft('allowed_extensions'), onChange: value => updateRouteList('allowed_extensions', value) }),
                  jsx(FormField, { label: 'Использовать watcher', type: 'checkbox', value: route.watcher_enabled, onChange: value => updateRoute('watcher_enabled', value) })
                ]
              }) : jsxs('div', {
                style: cardStyle,
                children: [
                  jsx(FormField, { label: 'Autopilot ID', value: route.autopilot_id, disabled: routeDestinationFieldLocked(route, 'autopilot_id'), onChange: value => updateRoute('autopilot_id', value) }),
                  jsx(FormField, { label: 'Trigger ID', value: route.trigger_id, disabled: routeDestinationFieldLocked(route, 'trigger_id'), onChange: value => updateRoute('trigger_id', value) }),
                  jsx(FormField, { label: 'Event', value: route.event, disabled: routeDestinationFieldLocked(route, 'event'), onChange: value => updateRoute('event', value) }),
                  jsx(FormField, { label: 'Разрешённые boards (через запятую)', value: routeListDraft('source_boards'), onChange: value => updateRouteList('source_boards', value) }),
                  jsx(FormField, { label: 'Разрешённые Hermes profiles', value: routeListDraft('allowed_profiles'), onChange: value => updateRouteList('allowed_profiles', value) }),
                  jsx(FormField, { label: 'Разрешённые assignees', value: routeListDraft('allowed_assignees'), onChange: value => updateRouteList('allowed_assignees', value) }),
                  jsx(FormField, { label: 'Требовать exact OperatorGrant', type: 'checkbox', value: route.operator_grant_required, onChange: value => updateRoute('operator_grant_required', value) }),
                  jsx(FormField, { label: 'Получать результат Multica', type: 'checkbox', value: route.result_tracking_enabled, onChange: value => updateRoute('result_tracking_enabled', value) })
                ]
              }),
              jsx(FormField, { label: 'Route включён', type: 'checkbox', value: route.enabled, disabled: route.tombstoned, onChange: value => updateRoute('enabled', value) }),
              jsx(Row, {
                label: 'Readiness',
                value: selectedRouteStatus?.configured
                  ? 'готов'
                  : (selectedRouteStatus?.readiness_errors || []).join(', ')
              }),
              jsx(Button, {
                onClick: removeRoute,
                children: (route.destination_locked || selectedRouteStatus?.latest_delivery)
                  ? 'Отключить и tombstone'
                  : 'Удалить Route из draft'
              })
            ]
          }) : null
        ]
      }),

      route?.operator_grant_required ? jsxs('section', {
        style: cardStyle,
        children: [
          jsx('h3', { children: '4. Operator grants выбранного Route' }),
          ...(registry.operator_grants || [])
            .filter(grant => grant.route_id === route.route_id)
            .map((grant, index) => jsxs('div', {
              style: rowButtonsStyle,
              children: [
                jsx('span', { children: `${grant.board} / ${grant.task_id}` }),
                jsx(Button, {
                  onClick: () => mutate(next => {
                    next.operator_grants = next.operator_grants.filter(item => !(
                      item.route_id === grant.route_id
                      && item.board === grant.board
                      && item.task_id === grant.task_id
                    ))
                  }),
                  children: 'Удалить'
                })
              ]
            }, `${grant.board}:${grant.task_id}:${index}`)),
          jsx(FormField, {
            label: 'Board',
            value: grantBoard,
            onChange: value => updateGrantDraft('board', value)
          }),
          jsx(FormField, {
            label: 'Task ID',
            value: grantTask,
            onChange: value => updateGrantDraft('task', value)
          }),
          jsx(Button, {
            onClick: addGrant,
            disabled: !grantBoard.trim() || !grantTask.trim(),
            children: '+ Grant'
          })
        ]
      }) : null,

      route && selectedRouteConnection?.security_mode === 'standard'
        ? jsx(CredentialEditor, {
            ctx,
            profile,
            route,
            connection: selectedRouteConnection,
            routeState: selectedRouteStatus,
            refresh
          })
        : null,
      route && selectedRouteConnection?.security_mode === 'isolated'
        ? jsx(IsolatedInstructions, { ctx, profile, routeId: route.route_id, refresh })
        : null
    ]
  })
}

function Diagnostics({ ctx, profile }) {
  const { status, error, loading, refresh } = useBridge(ctx, profile)
  return jsxs('div', {
    style: panelStyle,
    children: [
      jsx('h2', { children: 'Диагностика Routes' }),
      error ? jsx('div', { role: 'alert', children: error }) : null,
      loading ? jsx('div', { children: 'Проверка…' }) : null,
      ...(status?.routes || []).map(item => jsxs('section', {
        style: cardStyle,
        children: [
          jsx(Row, { label: 'Route ID', value: item.route_id }),
          jsx(Row, { label: 'Режим', value: item.security_mode }),
          jsx(Row, {
            label: 'Readiness',
            value: item.configured ? 'готов' : (item.readiness_errors || []).join(', ')
          }),
          item.security_mode === 'standard'
            ? jsx(Row, {
                label: 'Секреты',
                value: `webhook=${Boolean(item.secrets?.webhook_url)}, hmac=${Boolean(item.secrets?.hmac_signing_secret)}, pat=${Boolean(item.secrets?.multica_pat)}`
              })
            : null,
          item.security_mode === 'isolated'
            ? jsx(Row, { label: 'Socket', value: item.isolated_socket_path })
            : null,
          item.security_mode === 'isolated'
            ? jsx(Row, {
                label: 'Sender',
                value: item.isolated_sender_ready ? 'готов' : (item.isolated_sender_error_code || 'не готов')
              })
            : null,
          item.latest_delivery
            ? jsx(Row, {
                label: 'Последняя доставка',
                value: `${item.latest_delivery.delivery_status || '—'} / run ${item.latest_delivery.run_id || '—'} / result ${item.latest_delivery.result_status || '—'}`
              })
            : null
        ]
      }, item.route_id)),
      jsx(Button, { onClick: () => void refresh(), children: 'Обновить' })
    ]
  })
}

function BridgePage({ ctx }) {
  const focusedProfile = useValue(host.state.focusedSessionProfile)
  const gatewayProfile = useValue(host.state.profile)
  const profile = focusedProfile || gatewayProfile || ''
  const [section, setSection] = useState('overview')
  const content = section === 'registry'
    ? jsx(RegistryEditor, { ctx, profile })
    : section === 'diagnostics'
      ? jsx(Diagnostics, { ctx, profile })
      : jsx(Overview, { ctx, profile })

  return jsxs('div', {
    children: [
      jsxs('nav', {
        style: { display: 'flex', flexWrap: 'wrap', gap: '8px', padding: '16px 16px 0' },
        children: [
          jsx(Button, { onClick: () => setSection('overview'), disabled: section === 'overview', children: 'Обзор' }),
          jsx(Button, { onClick: () => setSection('registry'), disabled: section === 'registry', children: 'Реестр' }),
          jsx(Button, { onClick: () => setSection('diagnostics'), disabled: section === 'diagnostics', children: 'Диагностика' })
        ]
      }),
      content
    ]
  })
}

export default {
  id: PLUGIN_ID,
  name: 'Multica Bridge',
  register(ctx) {
    ctx.register({
      id: 'multica-bridge-page',
      area: ROUTES_AREA,
      data: { path: '/multica-bridge' },
      render: () => jsx(BridgePage, { ctx })
    })
    ctx.register({
      id: 'multica-bridge-nav',
      area: SIDEBAR_NAV_AREA,
      data: { path: '/multica-bridge', label: 'Multica Bridge', codicon: 'plug' }
    })
  }
}
